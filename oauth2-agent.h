/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_AGENT_H
#define _OAUTH2_AGENT_H

int obtain_code_from_agent(char* code, char* code_challenge, oauth2_config* config);

#endif


