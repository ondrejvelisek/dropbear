/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-utils.h"
#include "http.h"

#include "oauth2-introspect.h"



int parse_introspection_response(oauth2_introspection *introspection, json_value *response, char* error) {
    TRACE(("Parsing introspection response"))
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        return -1;
    }
    introspection->active = 0;
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strcmp(key, "error") == 0) {
            if (error == NULL) {
                dropbear_log(LOG_ERR, "Error response received: %s", value->u.string.ptr);
            } else {
                strcpy(error, value->u.string.ptr);
            }
            return -1;
        }
        if (strcmp(key, "active") == 0) {
            introspection->active = value->u.boolean;
            TRACE(("Access token received"))
        }
        if (strcmp(key, "sub") == 0) {
            strcpy(introspection->sub, value->u.string.ptr);
            TRACE(("Subject received"))
        }
        if (strcmp(key, "scope") == 0) {
            strcpy(introspection->scope, value->u.string.ptr);
            TRACE(("Scope received %s", introspection->scope))
        }
    }
    if (!introspection->active) {
        dropbear_log(LOG_ERR, "No introspection info provided");
        return -1;
    }
    TRACE(("Introspection response parsed"))
    return 0;
}

int introspect_access_token(
        oauth2_introspection* introspection,
        char* access_token,
        char* introspection_endpoint,
        char* resource_server_id,
        char* resource_server_secret
) {
    TRACE(("introspect_access_token enter"))

    char body[10000];
    sprintf(body, "token=%s&client_id=%s&client_secret=%s",
            access_token,
            resource_server_id,
            resource_server_secret);

    json_value* response;
    if (make_http_request(introspection_endpoint, NULL, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error while receiving response");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    if (parse_introspection_response(introspection, response, NULL) < 0) {
        dropbear_log(LOG_ERR, "Error while parsing introspection response");
        json_value_free(response);
        return -1;
    }
    json_value_free(response);
    TRACE(("token introspected"))
    return 0;
}
