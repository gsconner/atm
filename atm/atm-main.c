/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char prompt[] = "ATM: ";

int main(int argc, char* argv[])
{
    FILE* file;
    unsigned char key[32];
    unsigned char iv[16];

    if (argc != 2) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    file = fopen(argv[1], "rb");
    if (file == NULL) {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    if (fread(key, 1, 32, file)) {
        if (fread(iv, 1, 16, file)) {
            ;
        }
        else {
            printf("Error opening ATM initialization file\n");
            return 64;
        }
    } else {
        printf("Error opening ATM initialization file\n");
        return 64;
    }

    char user_input[1000];

    ATM *atm = atm_create(key, iv);

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 1000,stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        if (atm->session == NULL) {
            printf("%s", prompt);
        }
        else {
            printf("ATM (%s): ", atm->session);
        }
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
