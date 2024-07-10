#include "ports.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <openssl/rand.h>

int main(int argc, char *argv[]) {
    FILE *bank, *atm;
    int size = sizeof(argv[1]);
    char* name = malloc(size);
    char* str1;
    char* str2;
    unsigned char key[32], iv[16];

    if (argc != 2) {
        printf("Usage: init <filename>\n");
        return 62;
    }

    name[0] = '\0';
    for (int i = 0; i < size; i++) {
        if (argv[1][i] == '/') {
            if (i != size-1) {
                name[i] = '\0';
                mkdir(name, S_IRWXU);
            }
        }
        
        name[i] = argv[1][i];
    }

    str1 = malloc(size+10);
    str2 = malloc(size+10);

    strcat(str1, argv[1]);
    strcat(str2, argv[1]);
    strcat(str1, ".atm");
    strcat(str2, ".bank");

    if(access(str1, F_OK) == 0 ) {
        printf("Error: one of the files already exists\n");
        return 63;
    } 

    if(access(str2, F_OK) == 0 ) {
        printf("Error: one of the files already exists\n");
        return 63;
    } 

    bank = fopen(str1, "w");
    atm = fopen(str2, "w");

    if(access(str1, F_OK) == 0 && access(str2, F_OK) == 0) {
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));

        for (int i = 0; i < 32; i++){
            fprintf(bank,"%c",key[i]);
            fprintf(atm,"%c",key[i]);
        }
        for (int i = 0; i < 16; i++){
            fprintf(bank,"%c",iv[i]);
            fprintf(atm,"%c",iv[i]);
        }

        fclose(bank);
        fclose(atm);

        printf("Successfully initialized bank state\n");
        return 0;
    } else {
        printf("Error creating initialization files\n");
        return 64;
    }
}
