#include "parse.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const int MAX_ARGS = 10;

void parse(char* command, char* args[MAX_ARGS], int* argc) {
    //printf("%s", command);
    if (command == NULL) {
        *argc = 0;
        return;
    }

    int i  = 0;
    int count = 0;
    while (command[i] != '\n' && command[i] != '\0') {
        if (command[i] != ' ') {
            int k = i;
            while (command[k] != ' ' && command[k] != '\n' && command[k] != '\0') {
                k++;
            }
            args[count] = malloc(k-i+1);
            memcpy(args[count], &command[i], (k-i));
            args[count][k-i] = '\0';
            //printf("%s\n", args[count]);
            count++;
            i = k;
            if (count >= MAX_ARGS) {
                break;
            }
        }
        else {
            i++;
        }
    }

    //printf("argc: %d\n", count);
    *argc = count;
}

void free_args(char** args, int count) {
    for (int i = 0; i < count; i++) {
        free(args[i]);
    }
}