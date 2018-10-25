/*
 * author: Ondrej Velisek <ondrejvelisek@gmail.com>
 */

#ifndef _STR_ARRAY_H
#define _STR_ARRAY_H

int str_set_replace_delimiter(char* replaced, char* set, char* delimiter);

short str_set_contains(char* set, char* value);

short str_set_is_subset(char* subset, char* set);

int str_set_union(char* union_result, char* set);

// TODO shouldn't really be here
int rand_string(char* string, int size);

#endif


