/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "http-front.h"


#define MAX_STR_SIZE 100000
#define MAX_CONNECTIONS 10
#define CLOSE_PATH "/close_window"


SERVING_REQUEST_FAILED = -1;
SERVING_REQUEST_COMPLETED = 0;
SERVING_REQUEST_CONTINUING = 1;
SERVING_REQUEST_CLOSE_BROWSER = 2;

//////// UTILS

int generate_window_id(char* str) {
    int size = 8;
    srand(time(NULL));
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    if (size) {
        --size;
        for (size_t n = 0; n <= size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size+1] = '\0';
    }
    TRACE(("New window ID generated: %s", str))
    return 0;
}

//////// HELPERs

short request_match(char *request, char *method, char *url) {
    char req_method[10];
    char req_url[10000];
    sscanf(request, "%s %s", req_method, req_url);
    if (method != NULL) {
        if (strcmp(req_method, method) != 0) {
            TRACE(("Request didn't match, because of method %s != %s", method, req_method))
            return 0;
        }
    }
    if (url != NULL) {
        if (strncmp(req_url, url, strlen(url)) != 0) {
            TRACE(("Request didn't match, because of url %s != %s", url, req_url))
            return 0;
        }
    }
    return 1;
}

int make_response(char* response, char* status, char* headers, char* body) {
    if (status == NULL) {
        if (body == NULL || strlen(body) == 0) {
            status = "204 No Content";
        } else {
            status = "200 OK";
        }
    }
    if (headers == NULL) {
        headers = "";
    }
    if (body == NULL) {
        body = "";
    }
    sprintf(response, "HTTP/1.1 %s\r\n"
                      "Content-Length: %d\r\n"
                      "Connection: close\r\n"
                      "%s\r\n"
                      "%s",
            status, strlen(body), headers, body);
    return 0;
}

//// INTERNAL
int make_close_response(char* response, char* close_window_id) {
    generate_window_id(close_window_id);
    char body[100000];
    sprintf(body, "<html>"
                  "  <head>"
                  "    <title>Closing window [%s]</title>"
                  "  </head>"
                  "  <body onload='sendCloseRequest()'>"
                  "    <h1>%s</h1>"
                  "    <script>"
                  "      function sendCloseRequest() {"
                  "        setTimeout(() => {"
                  "          var xhttp = new XMLHttpRequest();"
                  "          xhttp.open('GET', '%s', true);"
                  "          xhttp.send();"
                  "        }, 100)"
                  "      }"
                  "    </script>"
                  "  </body>"
                  "</html>\r\n",
            close_window_id,
            "Authentication successfull. You can close this window and go back you "
            "If not, please close it and return to application.",
            CLOSE_PATH);
    make_response(response, NULL, NULL, body);
    return 1;
}

int close_request_handler(char* response, char* close_window_id) {
    make_response(response, "204 No Content", NULL, NULL);
    // TODO: not possible since it would close all tabs.
//    if (close_browser(close_window_id) < 0) {
//        dropbear_log(LOG_WARNING, "Error closing browser window. Need to close manually");
//    }
    return 0;
}

int get_current_window_id(int* current_window_id) {
    TRACE(("getting current window id"))
    char command[] = "xprop -root _NET_ACTIVE_WINDOW | awk '{print $NF}'";

    char output[MAX_STR_SIZE];
    FILE *fp;

    TRACE(("executing: %s", command))
    if ((fp = popen(command, "r")) == NULL) {
        dropbear_log(LOG_ERR, "Error opening command pipe");
        return -1;
    }
    if (fgets(output, MAX_STR_SIZE, fp) == NULL) {
        dropbear_log(LOG_ERR, "No output got");
        pclose(fp);
        return -1;
    }
    if(pclose(fp))  {
        dropbear_log(LOG_ERR, "Command not found or exited with error status");
        return -1;
    }
    output[strlen(output)-1] = '\0';

    TRACE(("current window id got: %s", output))
    TRACE(("parsing window id string to int"))
    *current_window_id = (int)strtol(output, NULL, 0);
    TRACE(("window id string parsed to int: %d", *current_window_id))
    return 0;
}

int execute(char* command) {
    char command_full[10000];
    sprintf(command_full, "%s > /dev/null 2>&1", command);
    TRACE(("executing: %s", command_full))
    int ret = system(command_full);
    if (ret == -1) {
        return -1;
    } else {
        return WEXITSTATUS(ret);
    }
}

int focus_window(int window_id) {
    TRACE(("Focusing window with id %d", window_id))
    char command[10000];
    sprintf(command, "wmctrl -i -a %d", window_id);
    return execute(command);
}

int open_browser(char* url) {
    TRACE(("Opening browser"))
    // check for X-window
    if (getenv("DISPLAY") == NULL) return -1;

    char command[10000];

    sprintf(command, "xdg-open \"%s\" > /dev/null 2>&1", url);
    if (execute(command) == 0) return 0;

    sprintf(command, "open \"%s\" > /dev/null 2>&1", url);
    if (execute(command) == 0) return 0;

    TRACE(("Unable to open browser"))
    return -1;
}

int close_browser(char* close_window_id) {
    TRACE(("CLosing browser. Window ID: %s", close_window_id))
    char command[10000];
    sprintf(command, "wmctrl -c %s", close_window_id);
    return execute(command);
}


////// SERVER RELATED
int init_socket(int port_number) {

    int server_socket;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
        dropbear_log(LOG_ERR, "Initializing socket failed");
        return -1;
    }

    int one = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htons(INADDR_ANY);
    server_address.sin_port = htons(port_number);

    if (bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        dropbear_log(LOG_ERR, "Binding socket failed");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, MAX_CONNECTIONS) < 0){
        dropbear_log(LOG_ERR, "Listen socket failed");
        close(server_socket);
        return -1;
    }
    return server_socket;
}

typedef struct inter_state_t {
    void* exter_state;
    char* close_window_id;
    int original_window_id;
} inter_state;

int serve_connection(int connection, int(*request_handler)(char*, char*, void*), inter_state* inter_state) {

    int continue_listening = SERVING_REQUEST_CONTINUING;
    char request[MAX_STR_SIZE];
    char response[MAX_STR_SIZE];

    if (read(connection, request, MAX_STR_SIZE) < 0) {
        dropbear_log(LOG_ERR, "Reading incomimng request failed");
        return -1;
    }
    TRACE(("Request received"))

    if (request_match(request, "GET", CLOSE_PATH)) {
        TRACE(("Handling close window response"))
        if (close_request_handler(response, inter_state->close_window_id) < 0) {
            dropbear_log(LOG_ERR, "Handling close window response failed");
            return -1;
        }
        continue_listening = SERVING_REQUEST_COMPLETED;
    } else {
        if ((continue_listening = request_handler(request, response, inter_state->exter_state)) < 0) {
            dropbear_log(LOG_ERR, "Handling response failed");
            return -1;
        } else if (continue_listening == SERVING_REQUEST_CLOSE_BROWSER) {
            TRACE(("Making close response"))
            bzero(response, MAX_STR_SIZE);
            make_close_response(response, inter_state->close_window_id);
            if (inter_state->original_window_id < 0) {
                dropbear_log(LOG_WARNING, "No original window id provided. Can't focuse it");
            } else {
                TRACE(("Focusing original window"))
                if (focus_window(inter_state->original_window_id) < 0) {
                    dropbear_log(LOG_WARNING, "Error while focusing original window");
                }
            }
        }
    }

    TRACE(("Sending response"))

    if (write(connection, response, strlen(response)) < 0) {
        dropbear_log(LOG_ERR, "Writing response failed");
        return -1;
    }

    TRACE(("Request served"))
    return continue_listening;
}

/////// MIAN ENTRY POINT
int make_browser_request(char* request_url, int port, int(*request_handler)(char*, char*, void*), void* state) {

    TRACE(("Starting server at port %d", port))

    int original_window_id;
    if (get_current_window_id(&original_window_id) < 0) {
        dropbear_log(LOG_WARNING, "Getting current window id failed");
        original_window_id = -1;
    }

    int server_socket;
    if ((server_socket = init_socket(port)) < 0) {
        dropbear_log(LOG_ERR, "Starting server failed");
        return -1;
    }

    TRACE(("Server started"))

    if (open_browser(request_url) != 0) {
        dropbear_log(LOG_ERR, "Opening browser failed");
        close(server_socket);
        return -1;
    }
    TRACE(("Browser opened"))

    char close_window_id[100];
    inter_state inter_state = { state, close_window_id, original_window_id };
    int continue_listening = 1;
    while(continue_listening) {

        TRACE(("Waiting for connection"))

        int connection;
        if ((connection = accept(server_socket, (struct sockaddr*) NULL, NULL)) < 0) {
            dropbear_log(LOG_ERR, "Accepting connection failed");
            close(server_socket);
            return -1;
        }
        TRACE(("Connection accepted"))

        if ((continue_listening = serve_connection(connection, request_handler, &inter_state)) < 0) {
            dropbear_log(LOG_ERR, "Serving connection failed");
            close(connection);
            close(server_socket);
            return -1;
        }

        close(connection);
        TRACE(("Connection closed"))

    }
    close(server_socket);

    TRACE(("Server stopped"))

    return 0;
}

