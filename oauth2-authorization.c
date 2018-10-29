/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"

#include "str-set.h"
#include "oauth2-authorization.h"

#define AUTHORIZATION_FILE "oauth2-mappings"
#define AUTHORIZATION_DIR "/etc/oauth2-ssh/"
#define AUTHORIZATION_HOME_DIR ".oauth2-ssh/"

FILE* open_authorization_home_file() {
    char* home_path_p = getenv("HOME");
    if (home_path_p == NULL) {
        dropbear_log(LOG_ERR, "Enviromental variable HOME not found");
        return NULL;
    }
    char absolute_file_path[1000];
    strcpy(absolute_file_path, home_path_p);
    strcat(absolute_file_path, "/");
    strcat(absolute_file_path, AUTHORIZATION_HOME_DIR);
    strcat(absolute_file_path, AUTHORIZATION_FILE);
    return fopen(absolute_file_path, "r");
}

FILE* open_authorization_file() {
    char absolute_file_path[1000];
    strcpy(absolute_file_path, AUTHORIZATION_DIR);
    strcat(absolute_file_path, AUTHORIZATION_FILE);
    return fopen(absolute_file_path, "r");
}

int read_user_record(char* local_username, char* remote_subjects, FILE* file){
    char* line = NULL;
    size_t len;
    if (getline(&line, &len, file) < 0) {
        return -1;
    }
    sscanf(line, "%[^:\n]:%[^\n]",
           local_username,
           remote_subjects
    );
    if (line) {
        free(line);
    }
}

short is_present_in_etc(char* local_username, char* remote_subject) {
    dropbear_log(LOG_INFO, "is_present_in_etc enter");

    FILE* authorization_file = open_authorization_file();
    if (authorization_file == NULL) {
        dropbear_log(LOG_INFO, "Authorization mapping file not found in /etc/");
        return 0;
    }

    char local_username_tmp[1000];
    char remote_subjects_tmp[10000];
    while (read_user_record(local_username_tmp, remote_subjects_tmp, authorization_file) >= 0) {
        if (strcmp(local_username, local_username_tmp) == 0) {
            dropbear_log(LOG_INFO, "Authorization record for user %s found, %s", local_username, remote_subjects_tmp);
            if (str_set_contains(remote_subjects_tmp, remote_subject, ':')) {
                dropbear_log(LOG_INFO, "Record contains remote subject %s. Authorizing.", remote_subject);
                fclose(authorization_file);
                return 1;
            }
            dropbear_log(LOG_INFO, "Record for user %s does not contain remote subject %s", local_username, remote_subject);
        }
    }
    fclose(authorization_file);

    dropbear_log(LOG_INFO, "Authorization record for user %s not found in /etc/", local_username);
}

short is_present_in_home(char* remote_subject) {
    dropbear_log(LOG_INFO, "is_present_in_home enter");

    FILE* authorization_home_file = open_authorization_home_file();
    if (authorization_home_file == NULL) {
        dropbear_log(LOG_INFO, "Authorization mapping file not found in home folder");
        return 0;
    }

    char* line = NULL;
    size_t len = 0;
    if (getline(&line, &len, authorization_home_file) < 0) {
        dropbear_log(LOG_INFO, "Unable to read line");
        return 0;
    }
    line[strcspn(line, "\n")] = '\0';
    if (str_set_contains(line, remote_subject, ':')) {
        dropbear_log(LOG_INFO, "Authorization mapping contains remote subject %s", remote_subject);
        free(line);
        fclose(authorization_home_file);
        return 1;
    }
    if (line) {
        free(line);
    }

    dropbear_log(LOG_INFO, "Authorization mapping not found in home");
    return 0;
}

//////////////////// API ///////////////

short is_authorized(char* local_username, char* remote_subject) {
    dropbear_log(LOG_INFO, "Authorizing remote subject %s for access to local user %s", remote_subject, local_username);

    char authorized = 0;
    authorized = is_present_in_etc(local_username, remote_subject) || is_present_in_home(remote_subject);

    if (authorized) {
        dropbear_log(LOG_INFO, "Remote subject %s authorized to access local user %s", remote_subject, local_username);
    } else {
        dropbear_log(LOG_INFO, "Remote subject %s not authorized to access local user %s", remote_subject, local_username);
    }
    return authorized;
}
