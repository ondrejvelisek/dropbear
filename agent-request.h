/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"

#ifndef AGENT_REQUEST_H_
#define AGENT_REQUEST_H_

#define SSH_AGENTC_EXTENSION 27
#define SSH_AGENTC_EXTENSION_OAUTH2_CODE_REQUEST "oauth2"
#define SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE 1
#define SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE_FAILURE 2

buffer* send_agent_request(char type, buffer* data);

buffer* read_agent_request(int connection, char* type);

int write_agent_response(int connection, char type, buffer* data);

#endif
