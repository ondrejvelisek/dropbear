/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"
#include "oauth2-utils.h"
#include "http.h"
#include "qrcodegen.h"

#include "oauth2-device.h"

int parse_device_response(oauth2_device *device, json_value *response) {
    TRACE(("Parsing device authorization response"))
    if (response->type != json_object) {
        dropbear_log(LOG_ERR, "Unknown JSON structure received");
        return -1;
    }
    for (int i = 0; i < response->u.object.length; i++) {
        char* key = response->u.object.values[i].name;
        json_value* value = response->u.object.values[i].value;
        if (strcmp(key, "error") == 0) {
            dropbear_log(LOG_ERR, "Error response received: %s", value->u.string.ptr);
            return -1;
        }
        if (strcmp(key, "device_code") == 0) {
            strcpy(device->device_code, value->u.string.ptr);
            TRACE(("Device code received"))
        }
        if (strcmp(key, "user_code") == 0) {
            strcpy(device->user_code, value->u.string.ptr);
            TRACE(("User code received"))
        }
        if (strcmp(key, "verification_url") == 0) {
            strcpy(device->verification_uri, value->u.string.ptr);
            TRACE(("Verification url received"))
        }
        if (strcmp(key, "verification_uri") == 0) {
            strcpy(device->verification_uri, value->u.string.ptr);
            TRACE(("Verification uri received"))
        }
        if (strcmp(key, "verification_uri_complete") == 0) {
            strcpy(device->verification_uri_complete, value->u.string.ptr);
            TRACE(("Verification uri complete received"))
        }
        if (strcmp(key, "expires_in") == 0) {
            device->expires_at = time(NULL) + value->u.integer;
            TRACE(("Expires in param received %d", device->expires_at))
        }
        if (strcmp(key, "interval") == 0) {
            device->interval = value->u.integer;
            TRACE(("Interval param received %d", device->interval))
        }
    }
    if (strlen(device->device_code) == 0) {
        dropbear_log(LOG_ERR, "No device code received");
        return -1;
    }
    if (strlen(device->user_code) == 0) {
        dropbear_log(LOG_ERR, "No user code received");
        return -1;
    }
    if (strlen(device->verification_uri) == 0) {
        dropbear_log(LOG_ERR, "No verification uri received");
        return -1;
    }
    if (device->expires_at == 0) {
        TRACE(("No expires in param received"))
    }
    if (device->interval == 0) {
        TRACE(("No interval param received"))
    }
    if (strlen(device->verification_uri_complete) == 0) {
        TRACE(("No verification uri complete received"))
    }
    TRACE(("Device response parsed"))
    return 0;
}


int device_authorization_request(oauth2_device* device, oauth2_config* config) {
    TRACE(("device_authorization_request enter"))

    char scope_encoded[1000];
    str_set_replace_delimiter(scope_encoded, config->required_scopes, "%20");
    TRACE(("Scope array URL encoded %s", scope_encoded))

    char body[10000];
    sprintf(body, "client_id=%s&scope=%s",
            config->client.client_id,
            scope_encoded
    );

    json_value* response;
    if (make_http_request(config->issuer.device_endpoint, NULL, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error making device authorization request");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    if (parse_device_response(device, response) < 0) {
        dropbear_log(LOG_ERR, "Error while parsing device response");
        json_value_free(response);
        return -1;
    }
    json_value_free(response);
    TRACE(("Device authorization response parsed"))
    return 0;
}


int device_token_request(oauth2_token* token, oauth2_device* device, oauth2_config* config) {
    TRACE(("device_authorization_request enter"))

    // client secret is optional
    char client_secret_param[1000] = "";
    if (strlen(config->client.client_secret) > 0) {
        sprintf(client_secret_param, "client_secret=%s&",
                config->client.client_secret
        );
    }

    char body[10000];
    sprintf(body, "grant_type=%s&device_code=%s&client_id=%s&%s",
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            device->device_code,
            config->client.client_id,
            client_secret_param
    );

    json_value* response;
    if (make_http_request(config->issuer.token_endpoint, NULL, body, &response, json_parser) < 0) {
        dropbear_log(LOG_ERR, "Error making device token request");
        return -1;
    }
    if (response == NULL) {
        dropbear_log(LOG_ERR, "No response received");
        return -1;
    }
    char error[100];
    if (parse_token_response(token, response, error) < 0) {
        if (strcmp(error, "authorization_pending")) {
            json_value_free(response);
            return 2;
        } else if (strcmp(error, "slow_down")) {
            json_value_free(response);
            return 1;
        } else {
            dropbear_log(LOG_ERR, "Error while parsing token response");
            json_value_free(response);
            return -1;
        }
    }
    json_value_free(response);
    TRACE(("Token for device got"))
    return 0;
}

int get_qrcode(char* qrcode, oauth2_device* device, oauth2_config* config) {
    uint8_t qrcode_bitmap[qrcodegen_BUFFER_LEN_MAX];
    uint8_t qrcode_temp[qrcodegen_BUFFER_LEN_MAX];
    if (!qrcodegen_encodeText(device->verification_uri,
                             qrcode_temp, qrcode_bitmap, qrcodegen_Ecc_LOW,
                             qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                             qrcodegen_Mask_AUTO, true)) {
        return -1;
    }

    qrcode[0] = '\0';
    int size = qrcodegen_getSize(qrcode_bitmap);

    for (int x = 0; x < size+2; x++) {
        strcat(qrcode, "\xE2\x96\x88\xE2\x96\x88");
    }
    strcat(qrcode, "\n");
    for (int y = 0; y < size; y++) {
        strcat(qrcode, "\xE2\x96\x88\xE2\x96\x88");
        for (int x = 0; x < size; x++) {
            if (qrcodegen_getModule(qrcode_bitmap, x, y)) {
                strcat(qrcode, "\x20\x20");
            } else {
                strcat(qrcode, "\xE2\x96\x88\xE2\x96\x88");
            }
        }
        strcat(qrcode, "\xE2\x96\x88\xE2\x96\x88");
        strcat(qrcode, "\n");
    }
    for (int x = 0; x < size+2; x++) {
        strcat(qrcode, "\xE2\x96\x88\xE2\x96\x88");
    }
}

int poll_for_device_token(oauth2_token* token, oauth2_device* device, oauth2_config* config) {
    TRACE(("poll_for_device_token enter"))

    long pending_till = device->expires_at;
    if (pending_till < time(NULL)) {
        pending_till = time(NULL) + 300;
    }
    while(time(NULL) < pending_till) {
        long next_time = time(NULL) + device->interval;
        int ret;
        if ((ret = device_token_request(token, device, config)) == 0) {
            return 0;
        } else if (ret < 0) {
            return -1;
        }
        if (time(NULL) > next_time) {
            continue;
        }
        int sleeping_time = next_time - time(NULL);
        TRACE(("Going to sleep for %d seconds", sleeping_time))
        sleep(sleeping_time);
    }

    return -1;

}