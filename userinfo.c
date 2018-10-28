/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "http.h"
#include "oauth2-native.h"

// GOOGLE
//#define ISSUER "https://accounts.google.com"
//#define AUTHORIZATION_ENDPOINT "https://accounts.google.com/o/oauth2/v2/auth"
//#define TOKEN_ENDPOINT "https://oauth2.googleapis.com/token"
//#define USERINFO_ENDPOINT "https://www.googleapis.com/oauth2/v3/userinfo"
//#define DEVICE_ENDPOINT "https://accounts.google.com/o/oauth2/device/code"
//#define SCOPES_REQUIRED "https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile"
//#define SUPPORTED_CODE_CHALLENGE_METHODS "plain S256"
//#define CLIENT_ID "708451758224-o4sed0lsq43tgpqo9ghgd802iuh9jvcs.apps.googleusercontent.com"
//#define CLIENT_SECRET "XRPq3N5OtNkbxiXipwF0E-Vr" // Not real secret in case of native app
//#define REDIRECT_URI_PORT 22080
//#define REDIRECT_URI_PATH "/oauth2_callback"

// ELIXIR
#define ISSUER "https://login.elixir-czech.org/oidc/"
#define AUTHORIZATION_ENDPOINT "https://login.elixir-czech.org/oidc/authorize"
#define TOKEN_ENDPOINT "https://login.elixir-czech.org/oidc/token"
#define USERINFO_ENDPOINT "https://login.elixir-czech.org/oidc/userinfo"
#define DEVICE_ENDPOINT "https://login.elixir-czech.org/oidc/devicecode"
#define SUPPORTED_CODE_CHALLENGE_METHODS "plain S256"
#define CLIENT_ID "b602da80-1cae-4cc0-b315-51a98dffe740"
#define CLIENT_SECRET "" // Not real secret in case of native app
#define REDIRECT_URI_PORT 22080
#define REDIRECT_URI_PATH "/oauth2_callback"
#define SCOPES_REQUIRED "openid"

int main(int argc, char ** argv) {
    printf("Authenticating...\n");

    debug_trace = 1;

    oauth2_config config = {
            .version = 1,
            .issuer = {
                    .issuer = ISSUER,
                    .authorization_endpoint = AUTHORIZATION_ENDPOINT,
                    .token_endpoint = TOKEN_ENDPOINT,
                    .userinfo_endpoint = USERINFO_ENDPOINT,
                    .device_endpoint = DEVICE_ENDPOINT,
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
    if (obtain_token(&token, &config, NULL) < 0) {
        printf("Unable to get info about user\n");
        return -1;
    }

    printf("Authentication successfull!\n");

    oauth2_userinfo userinfo;
    get_userinfo(&userinfo, token.access_token, config.issuer.userinfo_endpoint);
    if (userinfo.name == NULL || strlen(userinfo.name) == 0) {
        printf("Hello, %s!\n", userinfo.sub);
    } else {
        printf("Hello! Your user id is %s\n", userinfo.name);
    }
}
