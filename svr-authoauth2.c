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
#include "oauth2.h"

void send_oauth2_config(oauth2_config* oauth2_config) {

    CHECKCLEARTOWRITE();

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_OAUTH2_CONFIG);

    buf_putbyte(ses.writepayload, oauth2_config->version);

    buf_putstring(ses.writepayload, oauth2_config->issuer, strlen(oauth2_config->issuer));

    buf_putstring(ses.writepayload, oauth2_config->authorization_endpoint, strlen(oauth2_config->authorization_endpoint));

    buf_putstring(ses.writepayload, oauth2_config->token_endpoint, strlen(oauth2_config->token_endpoint));

    buf_putstring(ses.writepayload, oauth2_config->token_introspection_endpoint, strlen(oauth2_config->token_introspection_endpoint));

    buf_putstring(ses.writepayload, oauth2_config->scopes_required, strlen(oauth2_config->scopes_required));

    buf_putstring(ses.writepayload, oauth2_config->code_challenge_methods_supported, strlen(oauth2_config->code_challenge_methods_supported));

    buf_putstring(ses.writepayload, oauth2_config->client_id, strlen(oauth2_config->client_id));

    buf_putstring(ses.writepayload, oauth2_config->client_secret, strlen(oauth2_config->client_secret));

    buf_putint(ses.writepayload, oauth2_config->redirect_uri_port);

    buf_putstring(ses.writepayload, oauth2_config->redirect_uri_path, strlen(oauth2_config->redirect_uri_path));

    encrypt_packet();
}

void receive_access_token(oauth2_config* oauth2_config) {

    char* access_token = NULL;
    unsigned int access_token_len;
    char* refresh_token = NULL;
    unsigned int refresh_token_len;

    access_token = buf_getstring(ses.payload, &access_token_len);
    refresh_token = buf_getstring(ses.payload, &refresh_token_len);

    if (is_access_token_valid(access_token, oauth2_config)) {
        store_access_token(access_token, refresh_token);
    } else {
        dropbear_log(LOG_WARNING,
                     "Invalid access token attempt. User: '%s'",
                     ses.authstate.pw_name);
        m_burn(access_token, access_token_len);
        m_free(access_token);
        m_burn(refresh_token, refresh_token_len);
        m_free(refresh_token);
        send_msg_userauth_failure(0, 1);
        return;
    }

    m_burn(access_token, access_token_len);
    m_free(access_token);
    m_burn(refresh_token, refresh_token_len);
    m_free(refresh_token);

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

    /* reserved to be able to adjust flow */
    unsigned char type = buf_getbyte(ses.payload);

    oauth2_config oauth2_config = {
            .version = 1,
            .issuer = DROPBEAR_SVR_OAUTH2_ISSUER,
            .authorization_endpoint = DROPBEAR_SVR_OAUTH2_AUTHORIZATION_ENDPOINT,
            .token_endpoint = DROPBEAR_SVR_OAUTH2_TOKEN_ENDPOINT,
            .token_introspection_endpoint = DROPBEAR_SVR_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT,
            .scopes_required =  DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED,
            .code_challenge_methods_supported = DROPBEAR_SVR_OAUTH2_CODE_CHALLENGE_METHODS_SUPPORTED,
            .client_id = DROPBEAR_SVR_OAUTH2_CLIENT_ID,
            .client_secret = DROPBEAR_SVR_OAUTH2_CLIENT_SECRET,
            .redirect_uri_port = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PORT,
            .redirect_uri_path = DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PATH
    };

    if (type == 0) {
        // OAuth2 config request
        send_oauth2_config(&oauth2_config);

    } else if (type == 1) {
        // OAuth2 access token request
        receive_access_token(&oauth2_config);

    } else {

        dropbear_log(LOG_ERR,
                     "ERROR: OAuth2 authentication method unsuitable request type '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_failure(0, 1);

    }

}
