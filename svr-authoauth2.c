/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "ssh.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"
#include "oauth2-utils.h"
#include "oauth2-native.h"
#include "oauth2-authorization.h"

void send_oauth2_config(oauth2_config* config) {

    CHECKCLEARTOWRITE();

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_OAUTH2_CONFIG);
    buf_put_oauth2_config(ses.writepayload, config);
    encrypt_packet();
}

void receive_access_token(oauth2_config* config) {

    oauth2_token token;
    buf_get_oauth2_token(ses.payload, &token);

    if (!is_token_valid(&token, config)) {
        dropbear_log(LOG_WARNING,
                     "Invalid access token attempt. User: '%s'",
                     ses.authstate.pw_name);
        m_burn(token.access_token, strlen(token.access_token));
        m_burn(token.refresh_token, strlen(token.refresh_token));
        send_msg_userauth_failure(0, 1);
        return;
    }

    oauth2_userinfo userinfo;
    if (get_userinfo(&userinfo, token.access_token, config->issuer.userinfo_endpoint) < 0) {
        dropbear_log(LOG_WARNING,
                     "Invalid access token attempt. User: '%s'",
                     ses.authstate.pw_name);
        m_burn(token.access_token, strlen(token.access_token));
        m_burn(token.refresh_token, strlen(token.refresh_token));
        send_msg_userauth_failure(0, 1);
        return;
    }
    m_burn(token.access_token, strlen(token.access_token));
    m_burn(token.refresh_token, strlen(token.refresh_token));

    if (!is_authorized(ses.authstate.pw_name, userinfo.sub)) {
        dropbear_log(LOG_WARNING,
                     "User %s (%s) is not authorized to access account %s",
                     userinfo.name, userinfo.sub, ses.authstate.pw_name);
        send_msg_userauth_failure(0, 1);
        return;
    }

    send_msg_userauth_success();

    dropbear_log(LOG_NOTICE,
                 "Successfull oauth2 authentication: Leaving method. User: '%s' from %s",
                 ses.authstate.pw_name,
                 svr_ses.addrstring);
}

/* Process a oauth2 auth request, sending success or failure messages as
 * appropriate */
void svr_auth_oauth2(int valid_user) {

    dropbear_log(LOG_WARNING,
                 "ENTER: Entering OAuth2 authentication method '%s' from %s",
                 ses.authstate.pw_name,
                 svr_ses.addrstring);

    oauth2_config config = {
            .version = 1,
            .issuer = {
                    .issuer = DROPBEAR_SVR_OAUTH2_ISSUER,
                    .authorization_endpoint = DROPBEAR_SVR_OAUTH2_AUTHORIZATION_ENDPOINT,
                    .token_endpoint = DROPBEAR_SVR_OAUTH2_TOKEN_ENDPOINT,
                    .userinfo_endpoint = DROPBEAR_SVR_OAUTH2_USERINFO_ENDPOINT,
                    .supported_code_challenge_methods = DROPBEAR_SVR_OAUTH2_SUPPORTED_CODE_CHALLENGE_METHODS
            },
            .client = {
                    .client_id = DROPBEAR_SVR_OAUTH2_CLIENT_ID,
                    .client_secret = DROPBEAR_SVR_OAUTH2_CLIENT_SECRET,
                    .redirect_uri_port = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PORT,
                    .redirect_uri_path = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PATH
            },
            .required_scopes = DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED
    };

    char type = buf_getbyte(ses.payload);
    if (type == 0) {
        // OAuth2 config request
        send_oauth2_config(&config);

    } else if (type == 1) {
        // OAuth2 access token request
        receive_access_token(&config);

    } else {

        dropbear_log(LOG_ERR,
                     "ERROR: OAuth2 authentication method unsuitable request type '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_failure(0, 1);

    }

}
