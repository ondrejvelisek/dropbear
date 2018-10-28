/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "oauth2-model.h"

#ifndef _OAUTH2_DEVICE_H
#define _OAUTH2_DEVICE_H

int device_authorization_request(oauth2_device* device, oauth2_config* config);

int get_qrcode(char* qrcode, oauth2_device* device, oauth2_config* config);

int poll_for_device_token(oauth2_token* token, oauth2_device* device, oauth2_config* config);

#endif


