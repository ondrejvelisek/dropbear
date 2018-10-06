/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _HTTP_FRONT_H
#define _HTTP_FRONT_H

int make_browser_request(char* request_url, int port, int(*request_handler)(char*, char*, void*), void* state);

int SERVING_REQUEST_FAILED;
int SERVING_REQUEST_COMPLETED;
int SERVING_REQUEST_CONTINUING;
int SERVING_REQUEST_CLOSE_BROWSER;

short request_match(char *request, char *method, char *url);
int make_response(char* response, char* status, char* headers, char* body);

#endif


