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

void send_oauth2_config_request() {
    TRACE(("enter send_oauth2_config_request"))

    fill_oauth2_request_header(ses.writepayload, 0); /* 0 = OAuth2 config request */
    encrypt_packet();

    TRACE(("leave send_oauth2_config_request"))
}

void send_oauth2_authentication_request(oauth2_token* token) {
    TRACE(("enter send_oauth2_authentication_request"))

    fill_oauth2_request_header(ses.writepayload, 1); // 1 = OAuth2 authentication request
    buf_put_oauth2_token(ses.writepayload, token);
    encrypt_packet();

    TRACE(("leave send_oauth2_authentication_request"))
}

void recv_msg_userauth_oauth2_config() {
    TRACE(("enter recv_msg_userauth_oauth2_config"))

    oauth2_config config;
    buf_get_oauth2_config(ses.payload, &config);

    oauth2_token token;
    if (obtain_token(&token, &config, NULL) < 0) {
        dropbear_exit("Getting Access token failed");
        return;
    }

    send_oauth2_authentication_request(&token);

    m_burn(token.access_token, strlen(token.access_token));
    m_burn(token.refresh_token, strlen(token.refresh_token));

    TRACE(("leave recv_msg_userauth_oauth2_config"))
}

void cli_auth_oauth2() {
    TRACE(("enter cli_auth_oauth2"))

    send_oauth2_config_request();

    TRACE(("leave cli_auth_oauth2"))
}
