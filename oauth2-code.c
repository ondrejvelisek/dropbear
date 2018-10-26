/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "str-set.h"
#include "oauth2-utils.h"
#include "http.h"
#include "http-front.h"

#include "oauth2-code.h"

#define REDIRECT_URI_AUTHORITY "http://localhost"

int exchange_code_for_token(oauth2_token* token, char* code, char* code_verifier, oauth2_config* config) {
    TRACE(("exchange_code_for_token enter"))

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(config->client.client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                config->client.client_secret
        );
    }

    char body[10000];
    sprintf(body, "grant_type=%s&code=%s&client_id=%s&%sredirect_uri=%s:%d%s&code_verifier=%s",
            "authorization_code",
            code,
            config->client.client_id,
            client_secret_param,
            REDIRECT_URI_AUTHORITY,
            config->client.redirect_uri_port,
            config->client.redirect_uri_path,
            code_verifier
    );

    json_value* response;
    if (make_http_request(config->issuer.token_endpoint, NULL, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error while receiving response");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    if (parse_token_response(token, response) < 0) {
        dropbear_log(LOG_ERR, "Error while parsing token response");
        json_value_free(response);
        return -1;
    }
    json_value_free(response);
    TRACE(("Code exchanged for token"))
    return 0;
}

typedef struct state_t {
    char* oauth2_state;
    char* redirect_uri_path;
    char* code;
} state;

int handle_authorization_code_request(char* request, char* response, state* state) {

    TRACE(("Parsing authorization code response"))
    char method[10];
    char uri[10000];
    sscanf(request, "%s %s %*s", method, uri);

    char* path;
    char* query_string;
    path = strtok (uri,"?#");
    query_string = strtok (NULL, "?#");

    TRACE(("Method %s, path %s", method, path))

    state->code[0] = 0;
    char received_state[100];
    char* query_param;
    char* query_string_parse_state;
    int param_index = 0;
    query_param = strtok_r(query_string, "&", &query_string_parse_state);
    while(query_param != NULL) {
        char* query_param_parse_state;
        char* query_key = strtok_r(query_param, "=", &query_param_parse_state);
        char* query_value = strtok_r(NULL, "=", &query_param_parse_state);

        if (strstr(query_key, "error") != NULL) {
            dropbear_log(LOG_ERR, "Authorization code response contains error: %s", query_value);
            return -1;
        } else if (strcmp(query_key, "code") == 0) {
            TRACE(("Code received"))
            strcpy(state->code, query_value);
        } else if (strcmp(query_key, "state") == 0) {
            TRACE(("OAuth2 state received"))
            strcpy(received_state, query_value);
        } else {
            TRACE(("Unknown query param: %s = %s", query_key, query_value))
        }
        query_param = strtok_r(NULL, "&", &query_string_parse_state);
    }

    if (strcmp(received_state, state->oauth2_state) != 0) {
        dropbear_log(LOG_ERR, "Received state does not match sent one : %s !=  %s", received_state, state->oauth2_state);
        return SERVING_REQUEST_FAILED;
    }

    if (state->code[0] == 0) {
        dropbear_log(LOG_ERR, "Authorization code response parsed successfully, but no code is present");
        return SERVING_REQUEST_FAILED;
    }
    TRACE(("Authorization code response parsed successfuly"))
    return SERVING_REQUEST_CLOSE_BROWSER;
}

int request_handler(char* request, char* response, state* state) {
    if (request_match(request, "GET", state->redirect_uri_path)) {
        TRACE(("Redirect uri Request on OAuth2 local server received"))
        return handle_authorization_code_request(request, response, state);
    } else {
        char method[10];
        char uri[10000];
        sscanf(request, "%s %s %*s", method, uri);
        TRACE(("Unknown request received. Continue listening. %s %s", method, uri))
        make_response(response, "404 Not Found", NULL, NULL);
        return SERVING_REQUEST_CONTINUING;
    }
}

int make_auth_uri(char* auth_uri, char* oauth2_state, char* code_challenge, oauth2_config* config) {

    if (!str_set_contains(config->issuer.supported_code_challenge_methods, "plain", NULL)) {
        dropbear_log(LOG_ERR, "Server does not support PKCE 'plain' method. Aborting.");
        return -1;
    }
    TRACE(("PKCE server support checked (OK)"))

    char scope_encoded[1000];
    str_set_replace_delimiter(scope_encoded, config->required_scopes, "%20");
    TRACE(("Scope array URL encoded %s", scope_encoded))

    sprintf(auth_uri, "%s?client_id=%s&redirect_uri=%s:%d%s&response_type=%s&scope=%s&state=%s&code_challenge_method=%s&code_challenge=%s",
            config->issuer.authorization_endpoint,
            config->client.client_id,
            REDIRECT_URI_AUTHORITY,
            config->client.redirect_uri_port,
            config->client.redirect_uri_path,
            "code",
            scope_encoded,
            oauth2_state,
            "plain",
            code_challenge
    );
    return 0;
}

int obtain_code(char* code, char* code_challenge, oauth2_config* config) {
    TRACE(("getting authorization code"))

    char oauth2_state[16];
    rand_string(oauth2_state, 12);
    TRACE(("OAuth2 state generated"))

    char redirect_uri_path[1000];
    strcpy(redirect_uri_path, config->client.redirect_uri_path);

    char auth_uri[10000];
    make_auth_uri(auth_uri, oauth2_state, code_challenge, config);
    TRACE(("Authorization uri assembled: %s", auth_uri))

    state state = { oauth2_state, redirect_uri_path, code };

    if (make_browser_request(auth_uri, config->client.redirect_uri_port, request_handler, &state) < 0) {
        dropbear_log(LOG_ERR, "Getting authorization code failed");
        return -1;
    }
    TRACE(("Authorization code obtained"))

    return 0;
}
