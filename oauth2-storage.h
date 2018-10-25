/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_STORAGE_H
#define _OAUTH2_STORAGE_H

int store_token(oauth2_token* token, oauth2_config* config);

short is_token_stored(oauth2_config* config);

int obtain_stored_token(oauth2_token* token, oauth2_config* config);

int remove_stored_token(oauth2_config* config);

#endif
