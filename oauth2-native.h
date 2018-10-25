/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _OAUTH2_NATIVE_H
#define _OAUTH2_NATIVE_H

#include "oauth2-model.h"

int obtain_token(oauth2_token* token, oauth2_config* config, char* mode_sequence);

short is_token_valid(oauth2_token* token, oauth2_config* config);

int get_userinfo(oauth2_userinfo* userinfo, char* access_token, char* userinfo_endpoint);

#endif
