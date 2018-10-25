/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"
#include "json.h"
#include "buffer.h"

#ifndef _OAUTH2_UTILS_H
#define _OAUTH2_UTILS_H

int parse_token_response(oauth2_token* token, json_value* response);

void buf_put_oauth2_config(buffer* buffer, oauth2_config* config);

void buf_get_oauth2_config(buffer* buffer, oauth2_config* config);

void buf_put_oauth2_token(buffer* buffer, oauth2_token* token);

void buf_get_oauth2_token(buffer* buffer, oauth2_token* token);

#endif


