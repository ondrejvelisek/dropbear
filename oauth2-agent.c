/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-utils.h"
#include "agent-request.h"

#include "oauth2-agent.h"

int obtain_token_from_agent(oauth2_token* token, oauth2_config* config) {
    TRACE(("obtain_token_from_agent enter"))

    buffer* request = buf_new(100000);
    buf_putstring(request, SSH_AGENTC_EXTENSION_OAUTH2_TOKEN_REQUEST, strlen(SSH_AGENTC_EXTENSION_OAUTH2_TOKEN_REQUEST));
    buf_put_oauth2_config(request, config);
    buf_setpos(request, 0);

    buffer* response = NULL;
    if ((response = send_agent_request(SSH_AGENTC_EXTENSION, request)) == NULL) {
        dropbear_log(LOG_ERR, "Sending agent request failed");
        return -1;
    }
    TRACE(("Agent's access token request sent. Receiving response"))

    char packet_type;
    if ((packet_type = buf_getbyte(response)) != SSH_AGENT_EXTENSION_OAUTH2_TOKEN_RESPONSE) {
        dropbear_log(LOG_ERR, "Unknown response type received (%x)", packet_type);
        return -1;
    }
    TRACE(("Agent's response type received %d. Receiving token.", packet_type))

    buf_get_oauth2_token(response, token);
    buf_free(response);

    TRACE(("Agent's access token response received"))
    return 0;
}
