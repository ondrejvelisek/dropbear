/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-storage.h"
#include "oauth2-refresh.h"
#include "oauth2-agent.h"
#include "oauth2-code.h"
#include "http.h"
#include "str-set.h"

#include "oauth2-native.h"

int obtain_token_from_store(oauth2_token* token, oauth2_config* config) {
    TRACE(("obtain_token_from_store enter"))
    if (obtain_stored_token(token, config) < 0) {
        TRACE(("Could not get access token from store"))
        return -1;
    }
    if (!is_token_valid(token, config)) {
        TRACE(("Access token is stored but not valid."))
        return -1;
    }
    TRACE(("Access token obtained from store"))
    return 0;
}

int obtain_token_by_refreshing_from_store(oauth2_token* token, oauth2_config* config) {
    TRACE(("obtain_token_by_refreshing_from_store enter"))
    if (obtain_stored_token(token, config) < 0) {
        TRACE(("Could not get refresh token from store"))
        return -1;
    }
    if (refresh_token(token, token->refresh_token, config) < 0) {
        TRACE(("Could not refresh access token"))
        return -1;
    }
    if (!is_token_valid(token, config)) {
        TRACE(("Token was refreshed but access token is still not valid"))
        return -1;
    }
    TRACE(("Token refreshed. Storing."))
    if (store_token(token, config) < 0) {
        dropbear_log(LOG_WARNING, "Unable to store token");
    } else {
        TRACE(("Token stored"))
    }
    return 0;
}

int obtain_token_with_code_flow(oauth2_token* token, oauth2_config* config) {
    TRACE(("obtain_token_with_code_flow enter"))
    char code_verifier[16];
    rand_string(code_verifier, 15);
    char code_challenge[16];
    strcpy(code_challenge, code_verifier);

    char code[1000];
    if (obtain_code(code, code_challenge, config)) {
        TRACE(("Could not get authorization code. Maybe browser is unavaliable."))
        return -1;
    }
    if (exchange_code_for_token(token, code, code_verifier, config) < 0) {
        dropbear_log(LOG_ERR, "Could not exchange authorization code for access token");
        return -1;
    }
    TRACE(("Token obtained with code flow (browser). Storing."))
    if (store_token(token, config) < 0) {
        dropbear_log(LOG_WARNING, "Unable to store token");
    } else {
        TRACE(("Token stored"))
    }
    return 0;
}

int obtain_token_with_device_flow(oauth2_token* token, oauth2_config* config) {
    // TODO
    dropbear_log(LOG_WARNING, "Device flow not implemented yet");
    return -1;
}

int parse_userinfo_response(oauth2_userinfo* userinfo, json_value* response) {
    TRACE(("parse_userinfo_response enter"))
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
        if (strcmp(key, "sub") == 0) {
            strcpy(userinfo->sub, value->u.string.ptr);
            TRACE(("Subject received %s", userinfo->sub))
        }
        if (strcmp(key, "name") == 0) {
            strcpy(userinfo->name, value->u.string.ptr);
            TRACE(("Name received %s", value->u.string.ptr))
        }
    }
    if (strlen(userinfo->sub) == 0) {
        dropbear_log(LOG_ERR, "No subject received");
        return -1;
    }
    if (strlen(userinfo->name) == 0) {
        TRACE(("No name received"))
    }
    TRACE(("Userinfo response parsed"))
    return 0;
}

int obtain_token_by_mode(oauth2_token* token, oauth2_config* config, char mode) {
    if (mode == 'S') {
        return obtain_token_from_store(token, config);
    } else
    if (mode == 'R') {
        return obtain_token_by_refreshing_from_store(token, config);
    } else
    if (mode == 'A') {
        return obtain_token_from_agent(token, config);
    } else
    if (mode == 'C') {
        return obtain_token_with_code_flow(token, config);
    } else
    if (mode == 'D') {
        return obtain_token_with_device_flow(token, config);
    } else {
        dropbear_log(LOG_WARNING, "Unknown mode '%c'. Skipping", mode);
        return -1;
    }
}

////////////////// API ////////////////

int obtain_token(oauth2_token* token, oauth2_config* config, char* mode_sequence) {
    TRACE(("obtain_token enter"))

    if (mode_sequence == NULL) {
        // default sequence is Store, Refresh, Agent, Code, Device
        mode_sequence = "SRACD";
    }

    for (int i = 0; i < strlen(mode_sequence); i++) {
        if (obtain_token_by_mode(token, config, mode_sequence[i]) >= 0) {
            TRACE(("Token obtained by mode '%c'", mode_sequence[i]))
            return 0;
        }
    }
    dropbear_log(LOG_WARNING, "No mode succeeded to obtain token");
    return -1;
}

short is_token_valid(oauth2_token* token, oauth2_config* config) {
    TRACE(("is_token_valid enter"))
    if (time(NULL) > token->expires_at) {
        TRACE(("Access token has expired"))
        return 0;
    }
    if (!str_set_is_subset(config->required_scopes, token->scopes)) {
        TRACE(("Access token have insufficient scopes"))
        return 0;
    }
    oauth2_userinfo userinfo;
    if (get_userinfo(&userinfo, token->access_token, config->issuer.userinfo_endpoint) < 0) {
        TRACE(("Access token is invalid. Unable to get userinfo."))
        return 0;
    }
    TRACE(("Token is valid"))
    return 1;
}

int get_userinfo(oauth2_userinfo* userinfo, char* access_token, char* userinfo_endpoint) {
    TRACE(("get_userinfo enter"))

    char authorization[10000];
    sprintf(authorization, "Bearer %s", access_token);

    json_value* response;
    if (make_http_request(userinfo_endpoint, authorization, NULL, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error making userinfo request");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No userinfo response received");
        return -1;
    }
    if (parse_userinfo_response(userinfo, response) < 0) {
        dropbear_log(LOG_ERR, "Error while parsing userinfo response");
        json_value_free(response);
        return -1;
    }
    json_value_free(response);
    TRACE(("Userinfo got"))
    return 0;
}
