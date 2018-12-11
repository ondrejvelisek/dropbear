/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-utils.h"
#include "agent-request.h"

#include "oauth2-agent.h"



int obtain_code_from_agent(char* code, char* code_challenge, oauth2_config* config) {
    TRACE(("obtain_code_from_agent enter"))

    buffer* request = buf_new(100000);
    buf_putstring(request, SSH_AGENTC_EXTENSION_OAUTH2_CODE_REQUEST, strlen(SSH_AGENTC_EXTENSION_OAUTH2_CODE_REQUEST));
    buf_put_oauth2_config(request, config, code_challenge);
    buf_setpos(request, 0);

    buffer* response = NULL;
    if ((response = send_agent_request(SSH_AGENTC_EXTENSION, request)) == NULL) {
        dropbear_log(LOG_ERR, "Sending agent request failed");
        return -1;
    }
    TRACE(("Agent's code request sent. Receiving response"))

    char packet_type = buf_getbyte(response);
    if (packet_type == SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE_FAILURE) {
        dropbear_log(LOG_ERR, "Failure agent response received");
        buf_free(response);
        return -1;
    } else if (packet_type != SSH_AGENT_EXTENSION_OAUTH2_CODE_RESPONSE) {
        dropbear_log(LOG_ERR, "Unknown response type received (%x)", packet_type);
        buf_free(response);
        return -1;
    }
    TRACE(("Agent's response type received %d. Extracting code.", packet_type))

    buf_get_oauth2_code(response, code);

    TRACE(("Agent's code response received"))
    return 0;
}
