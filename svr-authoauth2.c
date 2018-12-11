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
#include "str-set.h"
#include "oauth2-authorization.h"
#include "oauth2-introspect.h"
#include "http.h"



void receive_access_token() {

    char access_token[10000];
    char* source;
    unsigned int source_len;
    source = buf_getstring(ses.payload, &source_len);
    strlcpy(access_token, source, source_len + 1);
    m_free(source);

    oauth2_introspection introspection;
    if (introspect_access_token(
            &introspection,
            access_token,
            DROPBEAR_SVR_OAUTH2_INTROSPECTION_ENDPOINT,
            DROPBEAR_SVR_OAUTH2_RESOURCE_SERVER_ID,
            DROPBEAR_SVR_OAUTH2_RESOURCE_SERVER_SECRET
    ) < 0) {
        dropbear_log(LOG_WARNING,
                     "Invalid access token introspection attempt. User: '%s'",
                     ses.authstate.pw_name);
        m_burn(access_token, strlen(access_token));
        send_msg_userauth_failure(0, 1);
        return;
    }
    m_burn(access_token, strlen(access_token));

    if (!introspection.active) {
        dropbear_log(LOG_WARNING,
                     "Access token is invalid");
        send_msg_userauth_failure(0, 1);
        return;
    }

    if (!str_set_is_subset(DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED, introspection.scope)) {
        dropbear_log(LOG_WARNING,
                     "Client is not authorized to access the machine");
        send_msg_userauth_failure(0, 1);
        return;
    }

    if (!is_authorized(ses.authstate.pw_name, introspection.sub)) {
        dropbear_log(LOG_WARNING,
                     "User %s (%s) is not authorized to access account %s",
                     introspection.sub, ses.authstate.pw_name);
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

    char type = buf_getbyte(ses.payload);
    if (type == 1) {
        // OAuth2 access token request
        receive_access_token();

    } else {

        dropbear_log(LOG_ERR,
                     "ERROR: OAuth2 authentication method unsuitable request type '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_failure(0, 1);

    }

}
