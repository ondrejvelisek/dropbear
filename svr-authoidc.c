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
#include "oauth2-code.h"
#include "oauth2-authorization.h"

void send_oidc_config(oauth2_config* config) {
    dropbear_log(LOG_INFO, "enter send_oidc_config");

    CHECKCLEARTOWRITE();

    m_free(ses.authstate.code_verifier);
    char code_verifier[16];
    rand_string(code_verifier, 15);
    ses.authstate.code_verifier = malloc((strlen(code_verifier)+1)*sizeof(char));
    strcpy(ses.authstate.code_verifier, code_verifier);

    char code_challenge[16];
    strcpy(code_challenge, code_verifier); // TODO should be S256

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_OIDC_CONFIG);
    buf_put_oauth2_config(ses.writepayload, config, 1);
    buf_putstring(ses.writepayload, code_challenge, strlen(code_challenge));
    encrypt_packet();
}

void receive_code(oauth2_config* config) {
    dropbear_log(LOG_INFO, "enter receive_code");

    char code[1000];
    buf_get_oauth2_code(ses.payload, code);

    char code_verifier[16];
    strcpy(code_verifier, ses.authstate.code_verifier);
    m_free(ses.authstate.code_verifier);

    oauth2_token token;
    if (exchange_code_for_token(&token, code, code_verifier, config) < 0) {
        dropbear_log(LOG_WARNING,
                     "Invalid code exchange attempt. User: '%s'",
                     ses.authstate.pw_name);
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
                 "Successfull OIDC authentication: Leaving method. User: '%s' from %s",
                 ses.authstate.pw_name,
                 svr_ses.addrstring);
}

/* Process a OIDC auth request, sending success or failure messages as
 * appropriate */
void svr_auth_oidc(int valid_user) {

    dropbear_log(LOG_WARNING,
                 "ENTER: Entering OIDC authentication method '%s' from %s",
                 ses.authstate.pw_name,
                 svr_ses.addrstring);

    oauth2_config config = {
            .version = 1,
            .issuer = {
                    .issuer = DROPBEAR_SVR_OIDC_ISSUER,
                    .authorization_endpoint = DROPBEAR_SVR_OIDC_AUTHORIZATION_ENDPOINT,
                    .token_endpoint = DROPBEAR_SVR_OIDC_TOKEN_ENDPOINT,
                    .userinfo_endpoint = DROPBEAR_SVR_OIDC_USERINFO_ENDPOINT,
                    .device_endpoint = DROPBEAR_SVR_OIDC_DEVICE_ENDPOINT,
                    .supported_code_challenge_methods = DROPBEAR_SVR_OIDC_SUPPORTED_CODE_CHALLENGE_METHODS
            },
            .client = {
                    .client_id = DROPBEAR_SVR_OIDC_CLIENT_ID,
                    .client_secret = DROPBEAR_SVR_OIDC_CLIENT_SECRET,
                    .redirect_uri_port = DROPBEAR_SVR_OIDC_REDIRECT_URI_PORT,
                    .redirect_uri_path = DROPBEAR_SVR_OIDC_REDIRECT_URI_PATH
            },
            .required_scopes = DROPBEAR_SVR_OIDC_SCOPES_REQUIRED
    };

    char type = buf_getbyte(ses.payload);
    if (type == 0) {
        // OIDC config request
        send_oidc_config(&config);

    } else if (type == 1) {
        // OIDC authorization code request
        receive_code(&config);

    } else {

        dropbear_log(LOG_ERR,
                     "ERROR: OIDC authentication method unsuitable request type '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_failure(0, 1);

    }

}
