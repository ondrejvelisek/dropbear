/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _OAUTH2_H
#define _OAUTH2_H

typedef struct oauth2_config_t {
    char version;
    char* issuer;
    char* authorization_endpoint;
    char* token_endpoint;
    char* token_introspection_endpoint;
    char* scopes_required;
    char* code_challenge_methods_supported;
    char* client_id;
    char* client_secret;
    int redirect_uri_port;
    char* redirect_uri_path;
} oauth2_config;

int str_array_join(char* result, char array[][1000], char* delimiter);

int str_array_length(char array[][1000]);

int get_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config);

int refresh_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config);

short is_valid_access_token_stored(oauth2_config* oauth2_config);

short is_valid_refresh_token_stored(oauth2_config* oauth2_config);

short is_access_token_valid(char* access_token, oauth2_config* oauth2_config);

short is_refresh_token_valid(char* refresh_token, oauth2_config* oauth2_config);

int obtain_stored_access_token(char* access_token, char* refresh_token);

int store_access_token(char* access_token, char* refresh_token);

int obtain_new_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config);

#endif


