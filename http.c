/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include <curl/curl.h>
#include "http.h"
#include "json.h"

#define MAX_STR_SIZE 100000

static size_t mem_writer(char* src, size_t _, size_t size, char* dest) {
    strcat(dest, src);
    return size;
}

int json_parser(char* response, json_value** result, char* error_message) {
    json_settings settings = { 0 };
    *result = json_parse_ex(&settings, response, strlen(response), error_message);
    if (*result == NULL) {
        return -1;
    } else {
        return 0;
    }
}

int make_http_request(char* url, char* authorization, char* body, void* result, int(*parser)(char*, void*, char*)) {

    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist* headers = NULL;
        if (authorization != NULL) {
            char authorization_header[10000];
            sprintf(authorization_header, "Authorization: %s", authorization);
            headers = curl_slist_append(headers, authorization_header);
        }

        char response[MAX_STR_SIZE] = "";
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mem_writer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        if (body != NULL) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        }

        TRACE(("Sending request"));
        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);

        /* Check for errors */
        if(res != CURLE_OK) {
            dropbear_log(LOG_ERR, "HTTP request failed\n Curl error message: %s\n",
                         curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return -1;
        } else {
            TRACE(("Response successfully received"));
            if (parser != NULL) {
                char error_message[MAX_STR_SIZE];
                TRACE(("Parsing message"));
                if (parser(response, result, error_message) < 0) {
                    dropbear_log(LOG_ERR, "HTTP parser was not able to parse response\n"
                                          "Parser error message: %s \nResponse string: %s\n",
                                 error_message, response);
                    curl_easy_cleanup(curl);
                    curl_global_cleanup();
                    return -1;
                }
                TRACE(("Response successfully parsed"));
            } else {
                strcpy(result, response);
                TRACE(("No parser passed. Parsing default to string."));
            }
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
    } else {
        dropbear_log(LOG_ERR, "Curl library failed to initialize\n");
        curl_global_cleanup();
        return -1;
    }

    curl_global_cleanup();
    return 0;
}
