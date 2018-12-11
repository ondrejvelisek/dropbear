/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_INTROSPECT_H
#define _OAUTH2_INTROSPECT_H

int introspect_access_token(
        oauth2_introspection* introspection,
        char* access_token,
        char* introspection_endpoint,
        char* resource_server_id,
        char* resource_server_secret
);

#endif


