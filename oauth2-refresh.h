/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_REFRESH_H
#define _OAUTH2_REFRESH_H

int refresh_token(oauth2_token* token, char* refresh_token, oauth2_config* config);

#endif


