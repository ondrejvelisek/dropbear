/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-utils.h"
#include "http.h"

#include "oauth2-refresh.h"

int refresh_token(oauth2_token* token, char* refresh_token, oauth2_config* config) {
    TRACE(("refresh_token enter"))

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(config->client.client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                config->client.client_secret
        );
    }

    char body[10000];
    sprintf(body, "grant_type=%s&refresh_token=%s&client_id=%s&%s",
            "refresh_token",
            refresh_token,
            config->client.client_id,
            client_secret_param
    );

    json_value* response;
    if (make_http_request(config->issuer.token_endpoint, NULL, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error making refresh token request");
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
    TRACE(("Token refreshed"))
    return 0;
}
