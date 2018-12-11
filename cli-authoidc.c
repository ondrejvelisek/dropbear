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
#include "oauth2-agent.h"

void fill_oidc_request_header(buffer* buffer, unsigned char type) {
    buf_putbyte(buffer, SSH_MSG_USERAUTH_REQUEST);
    buf_putstring(buffer, cli_opts.username, strlen(cli_opts.username));
    buf_putstring(buffer, SSH_SERVICE_CONNECTION, SSH_SERVICE_CONNECTION_LEN);
    buf_putstring(buffer, AUTH_METHOD_OIDC, AUTH_METHOD_OIDC_LEN);
    buf_putbyte(buffer, type);
}

void send_oidc_config_request() {
    TRACE(("enter send_oidc_config_request"))

    fill_oidc_request_header(ses.writepayload, 0); /* 0 = OIDC config request */
    encrypt_packet();

    TRACE(("leave send_oidc_config_request"))
}

void send_oidc_authentication_request(char* code) {
    TRACE(("enter send_oidc_authentication_request"))

    fill_oidc_request_header(ses.writepayload, 1); // 1 = OIDC authentication request
    buf_put_oauth2_code(ses.writepayload, code);
    encrypt_packet();

    TRACE(("leave send_oidc_authentication_request"))
}


void recv_msg_userauth_oidc_config() {
    TRACE(("enter recv_msg_userauth_oidc_config"))

    oauth2_config config;
    char code_challenge[1000];
    buf_get_oauth2_config(ses.payload, &config, code_challenge);

    char code[1000];
    if (obtain_code_from_agent(code, code_challenge, &config) < 0) {
        dropbear_exit("Getting Code failed");
        return;
    }

    send_oidc_authentication_request(code);

    TRACE(("leave recv_msg_userauth_oidc_config"))
}

void cli_auth_oidc() {
    TRACE(("enter cli_auth_oidc"))

    send_oidc_config_request();

    TRACE(("leave cli_auth_oidc"))
}
