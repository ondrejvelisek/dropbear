/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "dbutil.h"
#include "buffer.h"
#include "atomicio.h"

#include "agent-request.h"

int connect_agent() {
	TRACE(("connect_agent enter"))
	int fd = -1;
	char* agent_sock = NULL;

	agent_sock = getenv("SSH_AUTH_SOCK");
	if (agent_sock == NULL || strlen(agent_sock) == 0)
		return -1;

	fd = connect_unix(agent_sock);

	if (fd < 0) {
		dropbear_log(LOG_WARNING, "Failed to connect to agent");
	}

	return fd;
}

/////////////// API /////////////////////////

buffer* send_agent_request(char type, buffer* data) {
	TRACE(("send_agent_request enter"))
	buffer* response = NULL;

	int data_len = 0;
	if (data) {
		data_len = data->len;
	}

	buffer *payload;
	payload = buf_new(4 + 1 + data_len);

	buf_putint(payload, 1 + data_len);
	buf_putbyte(payload, type);
	if (data) {
		buf_putbytes(payload, data->data, data->len);
	}
	buf_setpos(payload, 0);

	TRACE(("Writing agent request bytes"))
	int socket;
	if ((socket = connect_agent()) < 0) {
        buf_free(payload);
        TRACE(("Unable to connect to socket"))
        goto out;
	}
	if (atomicio(vwrite, socket, buf_getptr(payload, payload->len), payload->len) != payload->len) {
		dropbear_log(LOG_ERR, "Write agent request failed, socket %d, %s", socket, strerror(errno));
		buf_free(payload);
		goto out;
	}
	buf_free(payload);

	TRACE(("Agent request bytes wrote"))
	TRACE(("Reading agent response length"))

	buffer* response_len_buf = buf_new(4);
	if (atomicio(read, socket, buf_getwriteptr(response_len_buf, 4), 4) != 4) {
		dropbear_log(LOG_ERR, "Read of agent response length failed");
		goto out;
	}
	buf_setpos(response_len_buf, 0);
	buf_setlen(response_len_buf, 4);
	size_t readlen = 0;
	readlen = buf_getint(response_len_buf);
	buf_free(response_len_buf);

	TRACE(("Agent response length read, %d", readlen))
	TRACE(("Reading agent response data"))

	response = buf_new(readlen);
	buf_setpos(response, 0);
	if (atomicio(read, socket, buf_getwriteptr(response, readlen), readlen) != readlen) {
		dropbear_log(LOG_ERR, "Read of agent response data failed");
		goto out;
	}
	buf_incrwritepos(response, readlen);
	buf_setlen(response, readlen);
	buf_setpos(response, 0);

	TRACE(("Agent response data read"))
out:
    m_close(socket);
	return response;
}

buffer* read_agent_request(int connection, char* type) {
	TRACE(("read_agent_request enter"))

	char request_len_str[4];
	if (read(connection, request_len_str, 4) < 0) {
		dropbear_log(LOG_ERR, "Error while reading request length");
		return NULL;
	}

	buffer* request_len_buf = buf_new(4);
	buf_putbytes(request_len_buf, request_len_str, 4);
	buf_setpos(request_len_buf, 0);
	int request_len = buf_getint(request_len_buf);
	buf_free(request_len_buf);

	TRACE(("Agent request length read %d", request_len))

    if (read(connection, type, 1) < 0) {
		dropbear_log(LOG_ERR, "Error while reading request type");
        return NULL;
    }

	TRACE(("Agent request type read %d", *type))

	char request_str[request_len - 1];
	if (read(connection, request_str, request_len - 1) < 0) {
		dropbear_log(LOG_ERR, "Error while reading request data");
		return NULL;
	}
	buffer* request_buf = buf_new(request_len - 1);
	buf_putbytes(request_buf, request_str, request_len - 1);
	buf_setpos(request_buf, 0);

	TRACE(("Agent request data read"))
	return request_buf;
}

int write_agent_response(int connection, char type, buffer* data) {
	TRACE(("write_agent_response enter"))

	buffer* response_len_buf = buf_new(4);
	int data_len = 0;
	if (data != NULL) {
		data_len = data->len;
	}
	buf_putint(response_len_buf, data_len + 1);

    if (write(connection, response_len_buf->data, 4) < 0) {
		dropbear_log(LOG_ERR, "Error writing agent response length");
        return -1;
	}
	buf_free(response_len_buf);
	TRACE(("Agent response length written"))

	if (write(connection, &type, 1) < 0) {
		dropbear_log(LOG_ERR, "Error writing agent response type");
        return -1;
	}
	TRACE(("Agent response type written"))

	if (data == NULL) {
		TRACE(("No agent response data to be written"))
	}
	if (write(connection, data->data, data->len) < 0) {
		dropbear_log(LOG_ERR, "Error writing agent response data");
		return -1;
	}
	TRACE(("Agent response data written"))
	return 0;
}