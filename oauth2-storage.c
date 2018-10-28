/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"

#include "oauth2-storage.h"

#define STORAGE_DIR ".oauth2-tokens/"

//////////////////// HELPER functions ///////////////

int home_path(char* home_path){
    char* home_path_p = getenv("HOME");
    if (home_path_p == NULL) {
        dropbear_log(LOG_ERR, "Enviromental variable HOME not found");
        return -1;
    }
    strcpy(home_path, home_path_p);
    strcat(home_path, "/");
    return 0;
}

int storage_path(char* storage_path){
    if (home_path(storage_path) < 0) {
        dropbear_log(LOG_ERR, "Error while getting oauth2 storage directory");
        return -1;
    }
    strcat(storage_path, STORAGE_DIR);
    return 0;
}

short file_exists(char* file_name){
    char absolute_file_path[1000];
    if (storage_path(absolute_file_path) < 0) {
        return 0;
    }
    strcat(absolute_file_path, file_name);
    struct stat buffer;
    return (stat(absolute_file_path, &buffer) == 0);
}

int make_dir(char* dir_name){
    char absolute_dir_path[1000];
    if (storage_path(absolute_dir_path) < 0) {
        return -1;
    }
    strcat(absolute_dir_path, dir_name);
    return mkdir(absolute_dir_path, 0700);
}

FILE* open_file(char* file_name, char* mode){
    char absolute_file_path[1000];
    if (storage_path(absolute_file_path) < 0) {
        return NULL;
    }
    if (!file_exists("")) {
        TRACE(("Creating new directory %s", STORAGE_DIR))
        make_dir("");
    }
    strcat(absolute_file_path, file_name);
    umask(0177);
    return fopen(absolute_file_path, mode);
}

int get_token_file_name(char* token_file_name, char* issuer){
    char token_end_file_name[10000];
    sanitize(token_end_file_name, issuer);
    if (storage_path(token_file_name) < 0) {
        return -1;
    }
    strcat(token_file_name, token_end_file_name);
    return 0;
}

FILE* open_token_file(char* issuer, char* mode){
    char token_file_name[10000];
    sanitize(token_file_name, issuer);
    return open_file(token_file_name, mode);
}

FILE* open_token_temp_file(char* issuer, char* mode){
    char token_temp_file_name[10000];
    sanitize(token_temp_file_name, issuer);
    strcat(token_temp_file_name, ".tmp");
    return open_file(token_temp_file_name, mode);
}

int replace_token_temp_file(char* issuer){
    char token_file_name[10000];
    if (get_token_file_name(token_file_name, issuer) < 0) {
        return -1;
    }
    char token_temp_file_name[10000];
    if (get_token_file_name(token_temp_file_name, issuer) < 0) {
        return -1;
    }
    strcat(token_temp_file_name, ".tmp");
    TRACE(("Moving file %s to %s", token_temp_file_name, token_file_name))
    umask(0177);
    return rename(token_temp_file_name, token_file_name);
}

int sanitize(char* sanitized, char* original){
    char position = 0;
    char sanitizer = '.';
    char char_sanitized = 0;
    char* allowed_chars = "_.-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < strlen(original); i++) {
        if (strchr(allowed_chars, original[i]) == NULL) {
            if (!char_sanitized) {
                sanitized[position] = sanitizer;
                char_sanitized = 1;
                position++;
            }
        } else {
            sanitized[position] = original[i];
            char_sanitized = 0;
            position++;
        }
    }
    sanitized[position] = '\0';
    return 0;
}

int read_record(char* client_id, oauth2_token* token, FILE* file){
    char* line = NULL;
    size_t len;
    if (getline(&line, &len, file) < 0) {
        return -1;
    }
    sscanf(line, "%[^;\n];%[^;\n];%d;%[^;\n];%[^;\n]",
           client_id,
           token->access_token,
           &(token->expires_at),
           token->refresh_token,
           token->scopes
    );
    if (line) {
        free(line);
    }
}

int write_record(char* client_id, oauth2_token* token, FILE* file){
    // TODO better handling of optional values
    char refresh_token_opt[1000];
    if (token->refresh_token == NULL || strlen(token->refresh_token) == 0) {
        strcpy(refresh_token_opt, " ");
    } else {
        strcpy(refresh_token_opt, token->refresh_token);
    }
    return fprintf(file, "%s;%s;%d;%s;%s\n",
                   client_id,
                   token->access_token,
                   token->expires_at,
                   refresh_token_opt,
                   token->scopes
    );
}

int append_token(oauth2_token* token, oauth2_config* config) {
    TRACE(("Appending access token to issuer %s", config->issuer.issuer, config->client.client_id))

    FILE* token_file = open_token_file(config->issuer.issuer, "a");
    write_record(config->client.client_id, token, token_file);
    fclose(token_file);

    TRACE(("Access token appended to issuer %s", config->issuer.issuer, config->client.client_id))
}

//////////////////// API ///////////////

int store_token(oauth2_token* token, oauth2_config* config) {
    TRACE(("Storing access token to issuer %s", config->issuer.issuer, config->client.client_id))

    if (remove_stored_token(config) < 0) {
        dropbear_log(LOG_ERR, "Error while removing access token");
        return -1;
    }
    if (append_token(token, config) < 0) {
        dropbear_log(LOG_ERR, "Error while appending new access token");
        return -1;
    }

    TRACE(("Access token stored to issuer %s", config->issuer.issuer, config->client.client_id))
}

short is_token_stored(oauth2_config* config) {
    TRACE(("Looking for access token to issuer %s", config->issuer.issuer, config->client.client_id))

    oauth2_token token_tmp;
    return obtain_stored_token(&token_tmp, config) >= 0;
}

int obtain_stored_token(oauth2_token* token, oauth2_config* config) {
    TRACE(("Obtaining access token to issuer %s", config->issuer.issuer, config->client.client_id))

    FILE* token_file = open_token_file(config->issuer.issuer, "r");
    if (token_file == NULL) {
        return -1;
    }

    char client_id_tmp[10000];
    oauth2_token token_tmp;

    while (read_record(client_id_tmp, &token_tmp, token_file) >= 0) {
        if (strcmp(client_id_tmp, config->client.client_id) == 0) {
            strcpy(token->access_token, token_tmp.access_token);
            token->expires_at = token_tmp.expires_at;
            strcpy(token->refresh_token, token_tmp.refresh_token);
            strcpy(token->scopes, token_tmp.scopes);
            TRACE(("Access token obtained to issuer %s", config->issuer.issuer, config->client.client_id))
            fclose(token_file);
            return 0;
        }
    }
    fclose(token_file);

    TRACE(("Access token not found to issuer %s", config->issuer.issuer, config->client.client_id))
    return -1;
}

int remove_stored_token(oauth2_config* config) {
    TRACE(("Removing access token to issuer %s", config->issuer.issuer, config->client.client_id))

    FILE* token_file = open_token_file(config->issuer.issuer, "r");
    if (token_file == NULL) {
        TRACE(("File for issuer %s not found. Nothing to remove.", config->issuer.issuer))
        return 0;
    }

    FILE* token_temp_file = open_token_temp_file(config->issuer.issuer, "w");
    if (token_temp_file == NULL) {
        dropbear_log(LOG_ERR, "Could not create temporary file while removing access token record", config->issuer.issuer);
        fclose(token_file);
        return -1;
    }

    char client_id_tmp[10000];
    oauth2_token token_tmp;
    int count = 0;
    while (read_record(client_id_tmp, &token_tmp, token_file) >= 0) {
        if (strcmp(client_id_tmp, config->client.client_id) == 0) {
            TRACE(("Access token for removing found"))
            count++;
        } else {
            write_record(client_id_tmp, &token_tmp, token_temp_file);
        }
    }

    fclose(token_file);
    fclose(token_temp_file);

    if (replace_token_temp_file(config->issuer.issuer) < 0) {
        dropbear_log(LOG_ERR, "Unable to replace temporary file");
        return -1;
    }

    TRACE(("%d access tokens removed to issuer %s", count, config->issuer.issuer, config->client.client_id))
}
