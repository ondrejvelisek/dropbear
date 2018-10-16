/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "buffer.h"
#include "dbutil.h"
#include "session.h"
#include "ssh.h"
#include "runopts.h"
#include "runopts.h"
#include "oauth2.h"

int recv_oauth2_config(oauth2_config* oauth2_config, buffer* payload) {

    oauth2_config->version = buf_getbyte(payload);
    TRACE(("OAuth2 config receiving. Version %d", oauth2_config->version))

    char* issuer;
    unsigned int issuer_len;
    issuer = buf_getstring(payload, &issuer_len);
    strncpy(oauth2_config->issuer, issuer, issuer_len);
    m_free(issuer);
    TRACE(("issuer %s", oauth2_config->issuer))

    char* authorization_endpoint;
    unsigned int authorization_endpoint_len;
    authorization_endpoint = buf_getstring(payload, &authorization_endpoint_len);
    strncpy(oauth2_config->authorization_endpoint, authorization_endpoint, authorization_endpoint_len);
    m_free(authorization_endpoint);
    TRACE(("authorization_endpoint %s", oauth2_config->authorization_endpoint))

    char* token_endpoint;
    unsigned int token_endpoint_len;
    token_endpoint = buf_getstring(payload, &token_endpoint_len);
    strncpy(oauth2_config->token_endpoint, token_endpoint, token_endpoint_len);
    m_free(token_endpoint);
    TRACE(("token_endpoint %s", oauth2_config->token_endpoint))

    char* token_introspection_endpoint;
    unsigned int token_introspection_endpoint_len;
    token_introspection_endpoint = buf_getstring(payload, &token_introspection_endpoint_len);
    strncpy(oauth2_config->token_introspection_endpoint, token_introspection_endpoint, token_introspection_endpoint_len);
    m_free(token_introspection_endpoint);
    TRACE(("token_introspection_endpoint %s", oauth2_config->token_introspection_endpoint))

    char* scopes_required;
    unsigned int scopes_required_len;
    scopes_required = buf_getstring(payload, &scopes_required_len);
    strncpy(oauth2_config->scopes_required, scopes_required, scopes_required_len);
    m_free(scopes_required);
    TRACE(("scopes_required %s", oauth2_config->scopes_required))

    char* code_challenge_methods_supported;
    unsigned int code_challenge_methods_supported_len;
    code_challenge_methods_supported = buf_getstring(payload, &code_challenge_methods_supported_len);
    strncpy(oauth2_config->code_challenge_methods_supported, code_challenge_methods_supported, code_challenge_methods_supported_len);
    m_free(code_challenge_methods_supported);
    TRACE(("code_challenge_methods_supported %s", oauth2_config->code_challenge_methods_supported))

    char* client_id;
    unsigned int client_id_len;
    client_id = buf_getstring(payload, &client_id_len);
    strncpy(oauth2_config->client_id, client_id, client_id_len);
    m_free(client_id);
    TRACE(("client_id %s", oauth2_config->client_id))

    char* client_secret;
    unsigned int client_secret_len;
    client_secret = buf_getstring(payload, &client_secret_len);
    strncpy(oauth2_config->client_secret, client_secret, client_secret_len);
    m_free(client_secret);
    TRACE(("client_secret %s", oauth2_config->client_secret))

    oauth2_config->redirect_uri_port = buf_getint(payload);
    TRACE(("redirect_uri_port %d", oauth2_config->redirect_uri_port))

    char* redirect_uri_path;
    unsigned int redirect_uri_path_len;
    redirect_uri_path = buf_getstring(payload, &redirect_uri_path_len);
    strncpy(oauth2_config->redirect_uri_path, redirect_uri_path, redirect_uri_path_len);
    m_free(redirect_uri_path);
    TRACE(("redirect_uri_path %s", oauth2_config->redirect_uri_path))

    TRACE(("OAuth2 config received"))

    return 0;
}

void recv_msg_userauth_oauth2_config() {

    char* str_oauth2_config = NULL;
    unsigned int str_oauth2_config_len = 0;

    TRACE(("enter recv_msg_userauth_oauth2_config"))

    char issuer[10000];
    char authorization_endpoint[10000];
    char token_endpoint[10000];
    char token_introspection_endpoint[10000];
    char scopes_required[10000];
    char code_challenge_methods_supported[10000];
    char client_id[10000];
    char client_secret[10000];
    char redirect_uri_path[10000];

    oauth2_config oauth2_config = {
            .version = 0,
            .issuer = issuer,
            .authorization_endpoint = authorization_endpoint,
            .token_endpoint = token_endpoint,
            .token_introspection_endpoint = token_introspection_endpoint,
            .scopes_required = scopes_required,
            .code_challenge_methods_supported = code_challenge_methods_supported,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri_port = 0,
            .redirect_uri_path = redirect_uri_path
    };

    recv_oauth2_config(&oauth2_config, ses.payload);

    m_free(str_oauth2_config);

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

    buf_putstring(ses.writepayload, cli_opts.username,
                  strlen(cli_opts.username));

    buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
                  SSH_SERVICE_CONNECTION_LEN);

    buf_putstring(ses.writepayload, AUTH_METHOD_OAUTH2,
                  AUTH_METHOD_OAUTH2_LEN);

    buf_putbyte(ses.writepayload, 1); /* OAuth2 access token request */

    TRACE(("getting access token"))

    char access_token[1000];
    char refresh_token[1000];
    if (cli_oauth2_get_access_token(oauth2_config.issuer, access_token) < 0) {
        dropbear_log(LOG_INFO, "Unable to connect to agent socket, trying to get token regularly");
        if (get_access_token(access_token, refresh_token, &oauth2_config) < 0) {
            dropbear_exit("Getting Access token failed");
            return;
        }
    }

    TRACE(("access token got"))
    TRACE(("sending access token"))

    buf_putstring(ses.writepayload, access_token, strlen(access_token));
    buf_putstring(ses.writepayload, refresh_token, strlen(refresh_token));

    encrypt_packet();
    m_burn(access_token, strlen(access_token));
    m_burn(refresh_token, strlen(refresh_token));

    TRACE(("access token sent"))

    TRACE(("leave recv_msg_userauth_oauth2_config"))
}

void cli_auth_oauth2() {

    TRACE(("enter cli_auth_oauth2"))

    buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

    buf_putstring(ses.writepayload, cli_opts.username,
                  strlen(cli_opts.username));

    buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION,
                  SSH_SERVICE_CONNECTION_LEN);

    buf_putstring(ses.writepayload, AUTH_METHOD_OAUTH2,
                  AUTH_METHOD_OAUTH2_LEN);

    buf_putbyte(ses.writepayload, 0); /* request OAuth2 config */

    encrypt_packet();

    TRACE(("leave cli_auth_oauth2"))
}
