/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "http.h"
#include "oauth2-native.h"

#define ISSUER "https://accounts.google.com"
#define AUTHORIZATION_ENDPOINT "https://accounts.google.com/o/oauth2/v2/auth"
#define TOKEN_ENDPOINT "https://oauth2.googleapis.com/token"
#define USERINFO_ENDPOINT "https://www.googleapis.com/oauth2/v3/userinfo"
#define SCOPES_REQUIRED "https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile"
#define SUPPORTED_CODE_CHALLENGE_METHODS "plain S256"
#define CLIENT_ID "708451758224-o4sed0lsq43tgpqo9ghgd802iuh9jvcs.apps.googleusercontent.com"
#define CLIENT_SECRET "XRPq3N5OtNkbxiXipwF0E-Vr" // Not real secret in case of native app
#define REDIRECT_URI_PORT 22080
#define REDIRECT_URI_PATH "/oauth2_callback"

int main(int argc, char ** argv) {
    printf("Authenticating...\n");

    oauth2_config config = {
            .version = 1,
            .issuer = {
                    .issuer = ISSUER,
                    .authorization_endpoint = AUTHORIZATION_ENDPOINT,
                    .token_endpoint = TOKEN_ENDPOINT,
                    .userinfo_endpoint = USERINFO_ENDPOINT,
                    .supported_code_challenge_methods = SUPPORTED_CODE_CHALLENGE_METHODS
            },
            .client = {
                    .client_id = CLIENT_ID,
                    .client_secret = CLIENT_SECRET,
                    .redirect_uri_port = REDIRECT_URI_PORT,
                    .redirect_uri_path = REDIRECT_URI_PATH
            },
            .required_scopes = SCOPES_REQUIRED
    };

    oauth2_token token;
    obtain_token(&token, &config, NULL);

    oauth2_userinfo userinfo;
    get_userinfo(&userinfo, token.access_token, config.issuer.userinfo_endpoint);
    printf("Hello, %s!\n", userinfo.name);
}
