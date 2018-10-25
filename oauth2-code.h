/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_CODE_H
#define _OAUTH2_CODE_H

int obtain_code(char* code, char* code_challenge, oauth2_config* config);

int exchange_code_for_token(oauth2_token* token, char* code, char* code_verifier, oauth2_config* config);

#endif


