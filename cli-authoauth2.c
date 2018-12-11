/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "buffer.h"
#include "dbutil.h"
#include "session.h"
#include "ssh.h"
#include "runopts.h"
#include "oauth2-utils.h"
#include "oauth2-native.h"

void fill_oauth2_request_header(buffer* buffer, unsigned char type) {
    buf_putbyte(buffer, SSH_MSG_USERAUTH_REQUEST);
    buf_putstring(buffer, cli_opts.username, strlen(cli_opts.username));
    buf_putstring(buffer, SSH_SERVICE_CONNECTION, SSH_SERVICE_CONNECTION_LEN);
    buf_putstring(buffer, AUTH_METHOD_OAUTH2, AUTH_METHOD_OAUTH2_LEN);
    buf_putbyte(buffer, type);
}

void send_oauth2_authentication_request(oauth2_config* config) {
    TRACE(("enter send_oauth2_authentication_request"))

    oauth2_token token;
    if (obtain_token(&token, config, NULL) < 0) {
        dropbear_exit("Getting Access token failed");
        return;
    }

    fill_oauth2_request_header(ses.writepayload, 1); // 1 = OAuth2 authentication request
    buf_putstring(ses.writepayload, token.access_token, strlen(token.access_token));
    encrypt_packet();

    TRACE(("leave send_oauth2_authentication_request"))
}

void cli_auth_oauth2() {
    TRACE(("enter cli_auth_oauth2"))
    
    oauth2_config config = {
            .version = 1,
            .issuer = {
                    .issuer = DROPBEAR_CLI_OAUTH2_ISSUER,
                    .authorization_endpoint = DROPBEAR_CLI_OAUTH2_AUTHORIZATION_ENDPOINT,
                    .token_endpoint = DROPBEAR_CLI_OAUTH2_TOKEN_ENDPOINT,
                    .userinfo_endpoint = DROPBEAR_CLI_OAUTH2_USERINFO_ENDPOINT,
                    .device_endpoint = DROPBEAR_CLI_OAUTH2_DEVICE_ENDPOINT,
                    .supported_code_challenge_methods = DROPBEAR_CLI_OAUTH2_SUPPORTED_CODE_CHALLENGE_METHODS
            },
            .client = {
                    .client_id = DROPBEAR_CLI_OAUTH2_CLIENT_ID,
                    .client_secret = DROPBEAR_CLI_OAUTH2_CLIENT_SECRET,
                    .redirect_uri_port = DROPBEAR_CLI_OAUTH2_REDIRECT_URI_PORT,
                    .redirect_uri_path = DROPBEAR_CLI_OAUTH2_REDIRECT_URI_PATH
            },
            .required_scopes = DROPBEAR_CLI_OAUTH2_SCOPES_REQUIRED
    };
    
    send_oauth2_authentication_request(&config);

    TRACE(("leave cli_auth_oauth2"))
}
