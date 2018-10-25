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
#include "oauth2-native.h"

buffer* oauth2_request_handler(buffer* data) {
    TRACE(("oauth2_request_handler enter"))

    oauth2_config config;
    buf_get_oauth2_config(data, &config);

    oauth2_token token;
    obtain_token(&token, &config, "SRCD");

    buffer* token_buf = buf_new(100000);
    buf_put_oauth2_token(token_buf, &token);
    buf_setpos(token_buf, 0);
    TRACE(("OAuth2 agent token response created"))
    return token_buf;
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

    if (strcmp(extension_type, SSH_AGENTC_EXTENSION_OAUTH2_TOKEN_REQUEST) != 0) {
        dropbear_log(LOG_WARNING, "Unknown extension type received (%s)", extension_type);
        m_free(extension_type);
        return NULL;
    }
    m_free(extension_type);

    buffer* response;
    response = oauth2_request_handler(request);
    *response_type = SSH_AGENT_EXTENSION_OAUTH2_TOKEN_RESPONSE;
    TRACE(("Agent response created"))
    return response;
}

int main(int argc, char ** argv) {
    debug_trace = 1;

    char path[] = "/tmp/oidc_sock";
    int sock;
    if (agent_init_socket(path, &sock) < 0) {
        dropbear_log(LOG_ERR, "Error while initializing socket");
        return -1;
    }
    agent_listen_on_socket(sock, agent_request_handler);

    unlink(path);
    close(sock);
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
        if ((response_buf = request_handler(request_type, request_buf, &response_type)) == NULL) {
            dropbear_log(LOG_ERR, "Error while handling request");
            buf_free(request_buf);
            close(connection);
            continue;
        }
        buf_free(request_buf);
        TRACE(("Request handled"))

        if (write_agent_response(connection, response_type, response_buf) < 0) {
            dropbear_log(LOG_ERR, "Error while writing response");
            buf_free(response_buf);
            close(connection);
            continue;
        }
        buf_free(response_buf);
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
        dropbear_log(LOG_ERR, "Error binding agent socket");
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
