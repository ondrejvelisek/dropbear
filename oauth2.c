/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2.h"
#include "http.h"
#include "http-front.h"

#define REDIRECT_URI_AUTHORITY "http://127.0.0.1"
#define STORED_TOKEN_LOCATION "/tmp/access_token"

///////  UTILS  ///////

int str_array_length(char array[][1000]) {
    for (int j = 0; j < 100; j++) {
        if (array[j][0] == NULL) {
            return j;
        }
    }
    return 0;
}

int str_array_join(char* result, char array[][1000], char* delimiter) {
    int position = 0;
    for (int i = 0; i < str_array_length(array); i++) {
        if (i != 0) {
            for (int j = 0; j < strlen(delimiter); j++) {
                result[position] = delimiter[j];
                position++;
            }
        }
        for (int j = 0; j < strlen(array[i]); j++) {
            result[position] = array[i][j];
            position++;
        }
    }
    result[position] = '\0';
    return 0;
}

int str_array_split(char result[][1000], char* str, char delimiter) {
    int position = 0;
    int item = 0;
    int item_position = 0;
    while (str[position] != '\0') {
        if (str[position] == delimiter) {
            result[item][item_position] = '\0';
            item++;
            position++;
            item_position = 0;
        } else {
            result[item][item_position] = str[position];
            position++;
            item_position++;
        }
    }
    result[item][item_position] = '\0';
    result[item + 1][0] = 0;
    return 0;
}

short str_array_contains(char arr[][1000], char* val){
    for (int i = 0; i < str_array_length(arr); i++) {
        if (strcmp(arr[i], val) == 0)
            return 1;
    }
    return 0;
}

short str_array_is_subset(char subset[][1000], char set[][1000]){
    for (int i = 0; i < str_array_length(subset); i++) {
        if (!str_array_contains(set, subset[i]))
            return 0;
    }
    return 1;
}

int str_array_push(char array[][1000], char* str){
    int len = str_array_length(array);
    strcpy(array[len], str);
    array[len+1][0] = '\0';
    return 0;
}

int str_array_union(char result[][1000], char set[][1000]){
    for (int i = 0; i < str_array_length(set); i++) {
        if (!str_array_contains(result, set[i])) {
            str_array_push(result, set[i]);
        }
    }
    return 0;
}

int rand_string(char* str, int size) {
    srand(time(NULL));
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    if (size) {
        --size;
        for (size_t n = 0; n <= size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size+1] = '\0';
    }
    return 0;
}

short file_exists(char* filename){
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

///////  MAIN API  ///////

int get_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config) {
    if (is_valid_access_token_stored(oauth2_config)) {
        TRACE(("Obtaining token from store"))
        if (obtain_stored_access_token(access_token, refresh_token) < 0) {
            dropbear_log(LOG_ERR, "Error while obtaining stored token");
            return -1;
        }
        TRACE(("Token obtained from store"))
    } else if (is_valid_refresh_token_stored(oauth2_config)) {
        TRACE(("Obtaining refresh token from store"))
        if (obtain_stored_access_token(access_token, refresh_token) < 0) {
            dropbear_log(LOG_ERR, "Error while obtaining stored token");
            return -1;
        }
        TRACE(("Refreshing token"))
        if (refresh_access_token(access_token, refresh_token, oauth2_config) < 0) {
            dropbear_log(LOG_ERR, "Error while refreshing token");
            return -1;
        }
        TRACE(("Storing token"))
        if (store_access_token(access_token, refresh_token) < 0) {
            dropbear_log(LOG_ERR, "Error while storing token");
            return -1;
        }
        TRACE(("Token refreshed and stored"))
    } else {
        TRACE(("Obtaining new token"))
        if (obtain_new_access_token(access_token, refresh_token, oauth2_config) < 0) {
            dropbear_log(LOG_ERR, "Error while obtaining new token");
            return -1;
        }
        TRACE(("Storing token"))
        if (store_access_token(access_token, refresh_token) < 0) {
            dropbear_log(LOG_ERR, "Error while storing token");
            return -1;
        }
        TRACE(("New token obtained and stored"))
    }
    return 0;
}

int refresh_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config) {
    TRACE(("Refreshing access token"))
    json_value* response;

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(oauth2_config->client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                oauth2_config->client_secret
        );
    }

    char body[10000];
    sprintf(body, "grant_type=%s&refresh_token=%s&client_id=%s&%s",
            "refresh_token",
            refresh_token,
            oauth2_config->client_id,
            client_secret_param
    );
    if (make_http_request(oauth2_config->token_endpoint, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error making refresh token request");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        json_value_free(response);
        return -1;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strstr(key, "error") != NULL) {
            dropbear_log(LOG_ERR, "Error response received while refreshing %s", value->u.string.ptr);
            json_value_free(response);
            return -1;
        }
        if (strcmp(key, "access_token") == 0) {
            TRACE(("Refreshed access token received"))
            strcpy(access_token, value->u.string.ptr);
        }
        if (strcmp(key, "refresh_token") == 0) {
            TRACE(("Refreshed refresh token received"))
            strcpy(refresh_token, value->u.string.ptr);
        }
    }
    TRACE(("Token refreshed"))
    json_value_free(response);
    return 0;
}

short is_valid_access_token_stored(oauth2_config* oauth2_config) {
    TRACE(("Checking if valid access token is stored"))
    if (!file_exists(STORED_TOKEN_LOCATION)) {
        TRACE(("Token file does not exists at location %s", STORED_TOKEN_LOCATION))
        return 0;
    }
    char access_token[1000];
    if (obtain_stored_access_token(access_token, NULL) < 0) {
        dropbear_log(LOG_ERR, "Error obtaining stored access token");
        return 0;
    }
    if (access_token == NULL || strlen(access_token) == 0) {
        TRACE(("No access token stored"))
        return 0;
    }
    TRACE(("Access token is stored. Validating"))
    return is_access_token_valid(access_token, oauth2_config);
}

short is_valid_refresh_token_stored(oauth2_config* oauth2_config) {
    TRACE(("Checking if valid refresh token is stored"))
    if (!file_exists(STORED_TOKEN_LOCATION)) {
        TRACE(("Token file does not exists at location %s", STORED_TOKEN_LOCATION))
        return 0;
    }
    char refresh_token[1000];
    if (obtain_stored_access_token(NULL, refresh_token) < 0) {
        dropbear_log(LOG_ERR, "Error obtaining stored refresh token");
        return 0;
    }
    if (refresh_token == NULL ||  strlen(refresh_token) == 0) {
        TRACE(("No refresh token stored"))
        return 0;
    }
    TRACE(("Refresh token is stored. Validating"))
    return is_refresh_token_valid(refresh_token, oauth2_config);
}

short is_access_token_valid(char* access_token, oauth2_config* oauth2_config) {
    TRACE(("Checking if access token is valid"))
    json_value* response;
    char url[10000];
    sprintf(url, "%s?access_token=%s", oauth2_config->token_introspection_endpoint, access_token);
    if (make_http_request(url, NULL, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error while making access toknen validation request");
        return 0;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return 0;
    }
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        json_value_free(response);
        return 0;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strstr(key, "error") != NULL) {
            dropbear_log(LOG_WARNING, "Access token is not valid");
            json_value_free(response);
            return 0;
        }
        // TODO check more things (issuer, audience/client)
        if (strcmp(key, "exp") == 0) {
            long expiration = strtol("012", value->u.string.ptr, 0);
            long current = time(NULL);
            if (expiration > current) {
                TRACE(("Access token expired"))
                json_value_free(response);
                return 0;
            }
        }
        if (strcmp(key, "scope") == 0) {
            char scope_arr_present[100][1000];
            str_array_split(scope_arr_present, value->u.string.ptr, ' ');
            char scope_arr_required[100][1000];
            str_array_split(scope_arr_required, oauth2_config->scopes_required, ' ');
            if (!str_array_is_subset(scope_arr_required, scope_arr_present)) {
                TRACE(("Access token has insufficient scope"))
                json_value_free(response);
                return 0;
            }
        }

    }
    TRACE(("Access token is valid"))
    json_value_free(response);
    return 1;
}

short is_refresh_token_valid(char* refresh_token, oauth2_config* oauth2_config) {
    TRACE(("Checking if refresh token is valid"))
    json_value* response;

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(oauth2_config->client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                oauth2_config->client_secret
        );
    }

    char body[10000];
    sprintf(body, "grant_type=%s&refresh_token=%s&client_id=%s&%s",
            "refresh_token",
            refresh_token,
            oauth2_config->client_id,
            client_secret_param
    );
    if (make_http_request(oauth2_config->token_endpoint, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error while making refresh token validation request");
        return 0;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return 0;
    }
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        json_value_free(response);
        return 0;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strstr(key, "error") != NULL) {
            TRACE(("Refresh token is not valid"))
            json_value_free(response);
            return 0;
        }
        if (strcmp(key, "scope") == 0) {
            char scope_arr_present[100][1000];
            str_array_split(scope_arr_present, value->u.string.ptr, ' ');
            char scope_arr_required[100][1000];
            str_array_split(scope_arr_required, oauth2_config->scopes_required, ' ');
            if (!str_array_is_subset(scope_arr_required, scope_arr_present)) {
                TRACE(("Refresh token has insufficient scope"))
                json_value_free(response);
                return 0;
            }
        }
    }
    json_value_free(response);
    TRACE(("Refresh token valid"))
    return 1;
}

int store_access_token(char* access_token, char* refresh_token) {
    TRACE(("Storing tokens"))
    char* file_path = STORED_TOKEN_LOCATION;
    FILE *file;
    if ((file = fopen(STORED_TOKEN_LOCATION, "w")) == NULL) {
        dropbear_log(LOG_ERR, "Error while opening file %s", file_path);
        return -1;
    }
    if (fprintf(file, "%s\n%s", access_token, refresh_token) < 0) {
        dropbear_log(LOG_ERR, "Error while writing to file %s", file_path);
        fclose(file);
        return -1;
    }
    fclose(file);
    TRACE(("Token(s) successfully stored. File %s closed", file_path))
    return 0;
}

int obtain_stored_access_token(char* access_token, char* refresh_token) {
    TRACE(("Obtaining stored tokens"))
    char* file_path = STORED_TOKEN_LOCATION;
    FILE *file;
    if ((file = fopen(file_path, "r")) == NULL) {
        dropbear_log(LOG_ERR, "Error while opening file %s", file_path);
        return -1;
    }
    TRACE(("File %s opened", file_path))
    int chars_read;
    if (refresh_token == NULL) {
        TRACE(("Reading access token"))
        chars_read = fscanf(file, "%s\n%*s", access_token);
    } else if (access_token == NULL) {
        TRACE(("Reading refresh token"))
        chars_read = fscanf(file, "%*s\n%s", refresh_token);
    } else {
        TRACE(("Reading access and refresh token"))
        chars_read = fscanf(file, "%s\n%s", access_token, refresh_token);
    }
    if (chars_read == 0) {
        dropbear_log(LOG_ERR, "Error while reading file %s", file_path);
        fclose(file);
        return -1;
    }
    fclose(file);
    TRACE(("Token(s) successfully obtained. File %s closed", file_path))
    return 0;
}

int obtain_new_access_token(char* access_token, char* refresh_token, oauth2_config* oauth2_config) {
    TRACE(("Obtaining new token"))

    char code_verifier[16];
    rand_string(code_verifier, 12);
    TRACE(("Code verifier generated"))

    char ccms_array[10][1000];
    str_array_split(ccms_array, oauth2_config->code_challenge_methods_supported, ' ');
    if (!str_array_contains(ccms_array, "plain")) {
        dropbear_log(LOG_ERR, "Server does not support required PKCE method 'plain'. supported: %s", oauth2_config->code_challenge_methods_supported);
        return -1;
    }

    char code_challenge[16];
    strcpy(code_challenge, code_verifier);
    TRACE(("Code challenge created"))

    char code[1000];
    if (get_auth_code(code_challenge, code, oauth2_config)) {
        dropbear_log(LOG_ERR, "Error while getting auth code");
        return -1;
    }

    if (exchange_code_for_access_token(code, code_verifier, access_token, refresh_token, oauth2_config) < 0) {
        dropbear_log(LOG_ERR, "Error while exchanging code for access token");
        return -1;
    }
    TRACE(("New token obtained successfully"))
    return 0;
}

int exchange_code_for_access_token(char* code, char* code_verifier, char* access_token, char* refresh_token, oauth2_config* oauth2_config) {
    TRACE(("Exchanging code for token"))

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(oauth2_config->client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                oauth2_config->client_secret
        );
    }

    json_value* response;
    char body[10000];
    sprintf(body, "grant_type=%s&code=%s&client_id=%s&%sredirect_uri=%s:%d%s&code_verifier=%s",
            "authorization_code",
            code,
            oauth2_config->client_id,
            client_secret_param,
            REDIRECT_URI_AUTHORITY,
            oauth2_config->redirect_uri_port,
            oauth2_config->redirect_uri_path,
            code_verifier
    );
    if (make_http_request(oauth2_config->token_endpoint, body, &response, json_parser)) {
        dropbear_log(LOG_ERR, "Error while receiving response");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        json_value_free(response);
        return -1;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strstr(key, "error") != NULL) {
            dropbear_log(LOG_ERR, "Error response received: %s", value->u.string.ptr);
            json_value_free(response);
            return -1;
        }
        if (strcmp(key, "access_token") == 0) {
            TRACE(("Access token received"))
            strcpy(access_token, value->u.string.ptr);
        }
        if (strcmp(key, "refresh_token") == 0) {
            TRACE(("Refresh token received"))
            strcpy(refresh_token, value->u.string.ptr);
        }
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
        make_response(response, NULL, NULL, NULL);
        return SERVING_REQUEST_CONTINUING;
    }
}

int make_auth_uri(char* auth_uri, char* oauth2_state, char* code_challenge, oauth2_config* oauth2_config) {

    char ccms_array[10][1000];
    str_array_split(ccms_array, oauth2_config->code_challenge_methods_supported, ' ');
    if (!str_array_contains(ccms_array, "plain")) {
        dropbear_log(LOG_ERR, "Server does not support PKCE 'plain' method. Aborting.");
        return -1;
    }
    TRACE(("PKCE server support checked (OK)"))

    char scope_array[100][1000];
    str_array_split(scope_array, oauth2_config->scopes_required, ' ');
    char scope_encoded[1000];
    str_array_join(scope_encoded, scope_array, "%20");
    TRACE(("Scope array URL encoded %s", scope_encoded))

    sprintf(auth_uri, "%s?client_id=%s&redirect_uri=%s:%d%s&response_type=%s&scope=%s&state=%s&code_challenge_method=%s&code_challenge=%s",
            oauth2_config->authorization_endpoint,
            oauth2_config->client_id,
            REDIRECT_URI_AUTHORITY,
            oauth2_config->redirect_uri_port,
            oauth2_config->redirect_uri_path,
            "code",
            scope_encoded,
            oauth2_state,
            "plain",
            code_challenge
    );
    return 0;
}

int get_auth_code(char* code_challenge, char* code, oauth2_config* oauth2_config) {

    TRACE(("getting authorization code"))

    char oauth2_state[16];
    rand_string(oauth2_state, 12);
    TRACE(("OAuth2 state generated"))

    char redirect_uri_path[1000];
    strcpy(redirect_uri_path, oauth2_config->redirect_uri_path);

    char auth_uri[10000];
    make_auth_uri(auth_uri, oauth2_state, code_challenge, oauth2_config);
    TRACE(("Authorization uri assembled: %s", auth_uri))

    state state = { oauth2_state, redirect_uri_path, code };

    if (make_browser_request(auth_uri, oauth2_config->redirect_uri_port, request_handler, &state) < 0) {
        dropbear_log(LOG_ERR, "Getting authorization code failed");
        return -1;
    }
    TRACE(("Authorization code obtained"))

    return 0;
}






