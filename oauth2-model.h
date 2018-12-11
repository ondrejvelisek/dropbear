/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _OAUTH2_MODEL_H
#define _OAUTH2_MODEL_H

typedef struct oauth2_issuer_t {
    char issuer[1000];
    char authorization_endpoint[10000];
    char token_endpoint[10000];
    char userinfo_endpoint[10000];
    char device_endpoint[10000];
    char supported_code_challenge_methods[1000];
} oauth2_issuer;

typedef struct oauth2_client_t {
    char client_id[1000];
    char client_secret[1000];
    int redirect_uri_port;
    char redirect_uri_path[1000];
} oauth2_client;

typedef struct oauth2_config_t {
    char version;
    oauth2_issuer issuer;
    oauth2_client client;
    char required_scopes[10000];
} oauth2_config;

typedef struct oauth2_userinfo_t {
    char sub[1000];
    char name[1000];
} oauth2_userinfo;

typedef struct oauth2_token_t {
    char access_token[10000];
    char refresh_token[10000];
    int expires_at;
    char scopes[10000];
} oauth2_token;

typedef struct oauth2_introspection_t {
    char active;
    char sub[10000];
    char scope[1000];
} oauth2_introspection;

typedef struct oauth2_device_t {
    char device_code[1000];
    char user_code[100];
    char verification_uri[10000];
    char verification_uri_complete[10000];
    int expires_at;
    int interval;
} oauth2_device;

#endif
