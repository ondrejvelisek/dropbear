/*
 * Dropbear - a SSH2 server
 * SSH client implementation
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2004 by Mihnea Stoenescu
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "runopts.h"
#include "session.h"
#include "dbrandom.h"
#include "crypto_desc.h"
#include "netio.h"
#include "ssh.h"
#include "buffer.h"
#include "agent-request.h"
#include "oauth2-utils.h"
#include "oauth2-code.h"

#define SOCK_PATH "/tmp/oauth2_sock" // TODO support multiuser environment
#define LOG_PATH "/tmp/oauth2agent.log" // TODO better path

int sock = 0;

buffer* oauth2_request_handler(buffer* data) {
    TRACE(("oauth2_request_handler enter"))

    oauth2_config config;
    char code_challenge[1000];
    buf_get_oauth2_config(data, &config, code_challenge);

    char code[1000];
    if (obtain_code(code, code_challenge, &config) < 0) {
        dropbear_log(LOG_ERR, "Unable to obtain code");
        return NULL;
    }

    buffer* code_buf = buf_new(100000);
    buf_put_oauth2_code(code_buf, code);
    buf_setpos(code_buf, 0);
    TRACE(("OAuth2 agent code response created"))
    return code_buf;
}

buffer* agent_request_handler(char request_type, buffer* request, char* response_type) {
    TRACE(("agent_request_handler enter"))

    if (request_type != SSH_AGENTC_EXTENSION) {
        dropbear_log(LOG_WARNING, "Unknown packet type received (%d)", request_type);
        return NULL;
    }

    char* extension_type;
    int extension_type_len;
    extension_type = buf_getstring(request, &extension_type_len);

    TRACE(("Agent extension request type received"))

    if (strcmp(extension_type, SSH_AGENTC_EXTENSION_OAUTH2_CODE_REQUEST) != 0) {
        dropbear_log(LOG_WARNING, "Unknown extension type received (%s)", extension_type);
        m_free(extension_type);
        return NULL;
    }
    m_free(extension_type);

    buffer* response;
    if ((response = oauth2_request_handler(request)) == NULL) {
        *response_type = SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE_FAILURE;
    } else {
        *response_type = SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE;
    }
    TRACE(("Agent response created"))
    return response;
}

void quit_signal_handler(int signum) {
    printf("Handling quit signal %d\n", signum);
    unlink(SOCK_PATH);
    close(sock);
    exit(signum);
}

int exec(char* command) {
    char command_full[10000];
//    sprintf(command_full, "%s > /dev/null 2>&1", command);
    sprintf(command_full, "%s", command);
    TRACE(("executing: %s", command_full))
    int ret = system(command_full);
    if (ret == -1) {
        return -1;
    } else {
        return WEXITSTATUS(ret);
    }
}

int kill_siblings() {
    char command[1000];
    sprintf(command, "kill $(pgrep $(cat /proc/%d/comm) | grep -v %d)", getpid(), getpid());
    return exec(command);
}

int daemonize() {

    daemon(0, 0);

    int log_fileno;
    if ((log_fileno = fileno(fopen(LOG_PATH, "a"))) < 0) {
        dropbear_log(LOG_ERR, "Error opening log file");
    } else {
        if (dup2(log_fileno, STDOUT_FILENO) < 0) {
            dropbear_log(LOG_ERR, "Error redirecting stdout to log file");
        }
        if (dup2(log_fileno, STDERR_FILENO) < 0) {
            dropbear_log(LOG_ERR, "Error redirecting stderr to log file");
        }
    }
}

int main(int argc, char ** argv) {

    char verbose = 0;
    char daemon = 0;

    char opt = 0;
    while ((opt = getopt(argc, argv, "vd")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = 1;
                break;
            case 'd':
                daemon = 1;
                break;
        }
    }

#if DEBUG_TRACE
    debug_trace = verbose;
#endif

    printf("export SSH_AUTH_SOCK=%s\n", SOCK_PATH);

    if (daemon) {
        daemonize();
    }
    kill_siblings();

    dropbear_log(LOG_INFO, "Starting OAuth2 agent");

    if (agent_init_socket(SOCK_PATH, &sock) < 0) {
        dropbear_log(LOG_ERR, "Error while initializing socket");
        return -1;
    }

    agent_listen_on_socket(sock, agent_request_handler);

    unlink(SOCK_PATH);
    close(sock);
    dropbear_log(LOG_INFO, "Quiting OAuth2 agent");
}

int agent_listen_on_socket(int sock, buffer* (*request_handler)(char, buffer*, char*)) {
    TRACE(("agent_listen_on_socket enter"))

    while (1) {
        TRACE(("Waiting for connection"))
        int connection;
        if ((connection = accept(sock, 0, 0)) < 0) {
            dropbear_log(LOG_ERR, "Error while accepting connection");
            perror("\n");
            break;
        }
        TRACE(("Connection accepted"))

        char request_type;
        buffer* request_buf;
        if ((request_buf = read_agent_request(connection, &request_type)) == NULL) {
            dropbear_log(LOG_ERR, "Error while reading request");
            close(connection);
            continue;
        }

        TRACE(("Request read"))

        char response_type;
        buffer* response_buf;
        response_buf = request_handler(request_type, request_buf, &response_type);
        buf_free(request_buf);
        TRACE(("Request handled"))

        if (write_agent_response(connection, response_type, response_buf) < 0) {
            dropbear_log(LOG_ERR, "Error while writing response");
            buf_free(response_buf);
            close(connection);
            continue;
        }
        if (response_buf) {
            buf_free(response_buf);
        }
        TRACE(("Response written"))
    }
}

int agent_init_socket(char* path, int* sock) {
    TRACE(("agent_init_socket enter"))
    if ((*sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        dropbear_log(LOG_ERR, "Error opening agent socket");
        return -1;
    }

    TRACE(("Agent socket created"))

    unlink(path);
    struct sockaddr_un server;
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, path);
    if (bind(*sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
        dropbear_log(LOG_ERR, "Error binding agent socket. Hint: try remove socket: %s", path);
        close(*sock);
        return -1;
    }

    TRACE(("Agent socket binded to %s", server.sun_path))

    if (listen(*sock, 5) < 0) {
        dropbear_log(LOG_ERR, "Error listen on agent socket");
        unlink(path);
        close(*sock);
        return -1;
    }
    TRACE(("Agent socket initialized"))
    return 0;
}
