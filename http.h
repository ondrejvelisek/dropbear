/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _HTTP_H
#define _HTTP_H

#include "json.h"

int json_parser(char* response, json_value** result, char* error_message);

int make_http_request(char* url, char* authorization, char* body, void* result, int(*parser)(char*, void*, char*));

#endif


