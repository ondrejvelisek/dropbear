/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#include "includes.h"

#define DELIMITER ' '
#define MAX_ARRAY_LEN 100
#define MAX_VALUE_LEN 1000

int str_array_length(char array[MAX_ARRAY_LEN][MAX_VALUE_LEN]) {
    for (int j = 0; j < 100; j++) {
        if (array[j][0] == NULL) {
            return j;
        }
    }
    return 0;
}

int str_set_join(char* result, char array[MAX_ARRAY_LEN][MAX_VALUE_LEN], char* delimiter) {
    int position = 0;
    for (int i = 0; i < str_array_length(array); i++) {
        if (i != 0) {
            for (int j = 0; j < strlen(delimiter); j++) {
                result[position] = delimiter[j];
                position++;
            }
        }
        for (int j = 0; j < strlen(array[i]); j++) {
            result[position] = array[i][j];
            position++;
        }
    }
    result[position] = '\0';
    return 0;
}

int str_set_split(char result[MAX_ARRAY_LEN][MAX_VALUE_LEN], char* str, char delimiter) {
    int position = 0;
    int item = 0;
    int item_position = 0;
    while (str[position] != '\0') {
        if (str[position] == delimiter) {
            result[item][item_position] = '\0';
            item++;
            position++;
            item_position = 0;
        } else {
            result[item][item_position] = str[position];
            position++;
            item_position++;
        }
    }
    result[item][item_position] = '\0';
    result[item + 1][0] = 0;
    return 0;
}

short str_array_contains(char arr[MAX_ARRAY_LEN][MAX_VALUE_LEN], char* val){
    for (int i = 0; i < str_array_length(arr); i++) {
        if (strcmp(arr[i], val) == 0)
            return 1;
    }
    return 0;
}

short str_array_is_subset(char subset[MAX_ARRAY_LEN][MAX_VALUE_LEN], char set[MAX_ARRAY_LEN][MAX_VALUE_LEN]){
    for (int i = 0; i < str_array_length(subset); i++) {
        if (!str_array_contains(set, subset[i]))
            return 0;
    }
    return 1;
}

int str_array_push(char array[MAX_ARRAY_LEN][MAX_VALUE_LEN], char* str){
    int len = str_array_length(array);
    strcpy(array[len], str);
    array[len+1][0] = '\0';
    return 0;
}

int str_array_union(char result[MAX_ARRAY_LEN][MAX_VALUE_LEN], char set[MAX_ARRAY_LEN][MAX_VALUE_LEN]){
    for (int i = 0; i < str_array_length(set); i++) {
        if (!str_array_contains(result, set[i])) {
            str_array_push(result, set[i]);
        }
    }
    return 0;
}

////////////////// API //////////////////////

int str_set_replace_delimiter(char* replaced, char* set, char* delimiter) {
    char array[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(array, set, DELIMITER);
    str_set_join(replaced, array, delimiter);
}

short str_set_contains(char* set, char* value) {
    char array[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(array, set, DELIMITER);
    return str_array_contains(array, value);
}

short str_set_is_subset(char* subset, char* set) {
    char subset_arr[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(subset_arr, subset, DELIMITER);
    char set_arr[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(set_arr, set, DELIMITER);
    return str_array_is_subset(subset_arr, set_arr);
}

int str_set_union(char* union_result, char* set1, char* set2) {
    char set1_arr[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(set1_arr, set1, DELIMITER);
    char set2_arr[MAX_ARRAY_LEN][MAX_VALUE_LEN];
    str_set_split(set2_arr, set2, DELIMITER);
    str_array_union(set1_arr, set2_arr);
    char delim_str[] = { DELIMITER, '\0' };
    return str_set_join(union_result, set1_arr, delim_str);
}

int rand_string(char* string, int size) {
    srand(time(NULL));
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
    if (size) {
        --size;
        for (size_t n = 0; n <= size; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            string[n] = charset[key];
        }
        string[size+1] = '\0';
    }
    return 0;
}