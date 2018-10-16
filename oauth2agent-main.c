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
#include "oauth2.h"

int oauth2agent_request_handler(char* request, buffer** payload) {

    // TODO parse oauth2 config from request
    oauth2_config oauth2_config = {
            .version = 1,
            .issuer = DROPBEAR_SVR_OAUTH2_ISSUER,
            .authorization_endpoint = DROPBEAR_SVR_OAUTH2_AUTHORIZATION_ENDPOINT,
            .token_endpoint = DROPBEAR_SVR_OAUTH2_TOKEN_ENDPOINT,
            .token_introspection_endpoint = DROPBEAR_SVR_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT,
            .scopes_required =  DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED,
            .code_challenge_methods_supported = DROPBEAR_SVR_OAUTH2_CODE_CHALLENGE_METHODS_SUPPORTED,
            .client_id = DROPBEAR_SVR_OAUTH2_CLIENT_ID,
            .client_secret = DROPBEAR_SVR_OAUTH2_CLIENT_SECRET,
            .redirect_uri_port = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PORT,
            .redirect_uri_path = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PATH
    };
    printf("Config read\n");
    printf("Obtaining access token\n");

    char access_token[10000];
    char refresh_token[10000];
    get_access_token(access_token, refresh_token, &oauth2_config);

    printf("Access token obtained\n");
    printf("Creating response\n");

    int len = 1 + 4 + strlen(access_token);

    *payload = buf_new(4 + len);

    buf_putint(*payload, len);
    buf_putbyte(*payload, SSH2_AGENT_OAUTH2_ACCESS_TOKEN_RESPONSE);
    buf_putstring(*payload, access_token, strlen(access_token));
    buf_setpos(*payload, 0);

    printf("Response created\n");
}

int main(int argc, char ** argv) {

	char path[] = "/tmp/oidc_sock";
	int sock;
	if (oauth2agent_init_socket(path, &sock) < 0) {
		perror("Error while initializing socket\n");
		return -1;
	}
	oauth2agent_listen_on_socket(sock, oauth2agent_request_handler);

	unlink(path);
	close(sock);
}

int oauth2agent_listen_on_socket(int sock, int(*request_handler)(char*, buffer*)) {

    printf("Listening on socket\n");
	char request_buf[4096];
	// TODO handle unlimited number of connections
	for (int i = 0; i < 10; i++) {
        printf("Waiting for connection\n");
		int connection;
		if ((connection = accept(sock, 0, 0)) < 0) {
			perror("Error while accepting connection\n");
			continue;
		}
		printf("Connection accepted\n");
		bzero(request_buf, sizeof(request_buf));
		if (read(connection, request_buf, 4096) < 0) {
			perror("Error while reading request\n");
			close(connection);
			continue;
		}
        printf("Request buffer read\n");
        printf("Handling request\n");

		buffer* response_buf;
		if (request_handler(request_buf, &response_buf) < 0) {
			perror("Error handling request\n");
			close(connection);
			continue;
		}
        printf("Request handled\n");

		if (write(connection, response_buf->data, response_buf->len + 4) < 0) {
			perror("Error writing to stream\n");
			close(connection);
			continue;
		}
	}
}

int oauth2agent_init_socket(char* path, int* sock) {
	if ((*sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("Error opening stream socket\n");
		return -1;
	}

	printf("Creating socket successfull\n");

    struct sockaddr_un server;

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, path);
	if (bind(*sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
		perror("Error binding stream socket\n");
		close(*sock);
		return -1;
	}

	printf("Socket has name %s\n", server.sun_path);

	if (listen(*sock, 5) < 0) {
        perror("Error listening socket\n");
		unlink(path);
        close(*sock);
        return -1;
	}
}
