/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"

#include "oauth2-utils.h"

void extract_buf_string(char* destination, buffer* response, char secret) {
    char* source;
    unsigned int source_len;
    source = buf_getstring(response, &source_len);
    strlcpy(destination, source, source_len + 1);
    m_free(source);
    if (secret) {
        TRACE(("OAuth2 string extracted: (secret of length %d)", strlen(destination)))
    } else {
        TRACE(("OAuth2 string extracted: %s", destination))
    }
}

///////////////// API ////////////////////

int parse_token_response(oauth2_token *token, json_value *response) {
    TRACE(("Parsing token repsonse"))
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        return -1;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strstr(key, "error") != NULL) {
            dropbear_log(LOG_ERR, "Error response received: %s", value->u.string.ptr);
            return -1;
        }
        if (strcmp(key, "access_token") == 0) {
            strcpy(token->access_token, value->u.string.ptr);
            TRACE(("Access token received"))
        }
        if (strcmp(key, "refresh_token") == 0) {
            strcpy(token->refresh_token, value->u.string.ptr);
            TRACE(("Refresh token received"))
        }
        if (strcmp(key, "expires_in") == 0) {
            token->expires_at = time(NULL) + value->u.integer;
            TRACE(("Expires in param received %d", token->expires_at))
        }
        if (strcmp(key, "scope") == 0) {
            strcpy(token->scopes, value->u.string.ptr);
            TRACE(("Scope received %s", token->scopes))
        }
    }
    if (strlen(token->access_token) == 0) {
        dropbear_log(LOG_ERR, "No access token received");
        return -1;
    }
    if (token->expires_at == 0) {
        TRACE(("No expires in param received"))
    }
    if (strlen(token->refresh_token) == 0) {
        TRACE(("No refresh token received"))
    }
    if (strlen(token->scopes) == 0) {
        TRACE(("No scope param received"))
    }
    TRACE(("Token repsonse parsed"))
    return 0;
}

void buf_put_oauth2_config(buffer* request, oauth2_config* config) {
    TRACE(("buf_put_oauth2_config enter"))
    buf_putbyte(request, config->version);
    buf_putstring(request, config->issuer.issuer, strlen(config->issuer.issuer));
    buf_putstring(request, config->issuer.authorization_endpoint, strlen(config->issuer.authorization_endpoint));
    buf_putstring(request, config->issuer.token_endpoint, strlen(config->issuer.token_endpoint));
    buf_putstring(request, config->issuer.userinfo_endpoint, strlen(config->issuer.userinfo_endpoint));
    buf_putstring(request, config->issuer.supported_code_challenge_methods, strlen(config->issuer.supported_code_challenge_methods));
    buf_putstring(request, config->client.client_id, strlen(config->client.client_id));
    buf_putstring(request, config->client.client_secret, strlen(config->client.client_secret));
    buf_putint(request, config->client.redirect_uri_port);
    buf_putstring(request, config->client.redirect_uri_path, strlen(config->client.redirect_uri_path));
    buf_putstring(request, config->required_scopes, strlen(config->required_scopes));
    TRACE(("OAuth2 config put to buffer"))
}

void buf_get_oauth2_config(buffer* response, oauth2_config* config) {
    TRACE(("buf_get_oauth2_config enter"))
    config->version = buf_getbyte(response);
    TRACE(("OAuth2 config version extracted: %d", config->version))
    extract_buf_string(config->issuer.issuer, response, 0);
    extract_buf_string(config->issuer.authorization_endpoint, response, 0);
    extract_buf_string(config->issuer.token_endpoint, response, 0);
    extract_buf_string(config->issuer.userinfo_endpoint, response, 0);
    extract_buf_string(config->issuer.supported_code_challenge_methods, response, 0);
    extract_buf_string(config->client.client_id, response, 0);
    extract_buf_string(config->client.client_secret, response, 1);
    config->client.redirect_uri_port = buf_getint(response);
    TRACE(("OAuth2 config redirect uri port extracted: %d", config->client.redirect_uri_port))
    extract_buf_string(config->client.redirect_uri_path, response, 0);
    extract_buf_string(config->required_scopes, response, 0);
    TRACE(("OAuth2 config got"))
}

void buf_put_oauth2_token(buffer* request, oauth2_token* token) {
    TRACE(("buf_put_oauth2_token enter"))
    buf_putstring(request, token->access_token, strlen(token->access_token));
    buf_putint(request, token->expires_at);
    buf_putstring(request, token->refresh_token, strlen(token->refresh_token));
    buf_putstring(request, token->scopes, strlen(token->scopes));
    TRACE(("OAuth2 token put"))
}

void buf_get_oauth2_token(buffer* response, oauth2_token* token) {
    TRACE(("buf_get_oauth2_token enter"))
    extract_buf_string(token->access_token, response, 1);
    token->expires_at = buf_getint(response);
    TRACE(("OAuth2 token expires_at extracted: %d", token->expires_at))
    extract_buf_string(token->refresh_token, response, 1);
    extract_buf_string(token->scopes, response, 0);
    TRACE(("OAuth2 token got"))
}
