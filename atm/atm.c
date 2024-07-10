#include "atm.h"
#include "parse/parse.h"
#include "ports.h"
#include "encryption.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

struct attempt_list* failed_login_attempt(struct attempt_list* attempts, char* user) {
    if (attempts == NULL) {
        attempts = malloc(sizeof(struct attempt_list));
        attempts->user = malloc(250);
        strcpy(attempts->user, user);
        attempts->attempts = 1;
        attempts->next = NULL;
    }
    else if (strcmp(attempts->user, user) == 0) {
        attempts->attempts += 1;
    }
    else {
        attempts->next = failed_login_attempt(attempts->next, user);
    }

    return attempts;
}

int get_attempts(struct attempt_list* attempts, char* user) {
    if (attempts == NULL) {
        return 0;
    }
    else if (strcmp(attempts->user, user) == 0) {
        return attempts->attempts;
    }
    else {
        return get_attempts(attempts->next, user);
    }
}

void free_attempts(struct attempt_list* attempts) {
    if (attempts != NULL) {
        free_attempts(attempts->next);
        free(attempts->user);
        free(attempts->next);
        attempts->next = NULL;
    }
}

ATM* atm_create(unsigned char key[32], unsigned char iv[16])
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    atm->session = NULL;
    atm->attempts = NULL;

    atm->key = malloc(32);
    atm->iv = malloc(16);

    memcpy(atm->key, key, 32);
    memcpy(atm->iv, iv, 16);

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, unsigned char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, unsigned char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

char* bank_send_command(ATM* atm, char* command) {
    unsigned char* plaintext = malloc(10000);
    int n;
    unsigned char ciphertext[128];
    int ciphertext_len;

    ciphertext_len = encrypt((unsigned char*)command, strlen(command), atm->key, atm->iv, ciphertext);

    //printf("sending: %s\n", ciphertext);

    atm_send(atm, ciphertext, ciphertext_len);
    n = atm_recv(atm,ciphertext,10000);

    //printf("ciphertext: %s\n", ciphertext);

    int decryptedtext_len;

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, n, atm->key, atm->iv,
                                plaintext);

    //printf("plaintext: %s", plaintext);

    plaintext[decryptedtext_len]=0;
    
    return (char*)plaintext;
}

char* create_command(char* args[MAX_ARGS], int num_args) {
    char* command = malloc(1000);
    command[0] = '\0';

    for (int i = 0; i < num_args; i++) {
        command = strcat(command, args[i]);
        command = strcat(command, " ");
    }
    command = strcat(command, "\n");

    return command;
}

int authenticate(ATM *atm, char* user) {
    char* send;
    char* response;
    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));
    int authenticated;

    char* sendargs[MAX_ARGS];
    for (int i = 0; i < 2; i++){
        sendargs[i] = malloc(1000);
    }
    strcpy(sendargs[0], "authenticate");
    strcpy(sendargs[1], user);

    send = create_command(sendargs, 2);
    response = bank_send_command(atm, send);

    parse(response, args, argc);

    authenticated = (*argc == 2 && strcmp(args[0], user) == 0 && strcmp(args[1], "authenticated") == 0);

    free_args(sendargs, 2);
    free(send);
    free(response);
    free_args(args, *argc);
    free(argc);

    return authenticated;
}

int send_card(ATM *atm, char* user, char* card) {
    char* send;
    char* response;
    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));
    int authenticated;

    char* sendargs[MAX_ARGS];
    for (int i = 0; i < 3; i++){
        sendargs[i] = malloc(1000);
    }
    strcpy(sendargs[0], "card");
    strcpy(sendargs[1], user);
    strcpy(sendargs[2], card);

    send = create_command(sendargs, 3);
    response = bank_send_command(atm, send);

    parse(response, args, argc);

    authenticated = (*argc == 3 && strcmp(args[0], user) == 0 && strcmp(args[1], card) == 0 && strcmp(args[2], "match") == 0);

    free_args(sendargs, 3);
    free(send);
    free(response);
    free_args(args, *argc);
    free(argc);

    return authenticated;
}

int send_pin(ATM *atm, char* user, char* pin) {
    char* send;
    char* response;
    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));
    int authenticated;

    char* sendargs[MAX_ARGS];
    for (int i = 0; i < 3; i++){
        sendargs[i] = malloc(1000);
    }
    strcpy(sendargs[0], "pin");
    strcpy(sendargs[1], user);
    strcpy(sendargs[2], pin);

    send = create_command(sendargs, 3);
    response = bank_send_command(atm, send);

    parse(response, args, argc);

    authenticated = (*argc == 3 && strcmp(args[0], user) == 0 && strcmp(args[1], pin) == 0 && strcmp(args[2], "correct") == 0);

    free_args(sendargs, 3);
    free(send);
    free(response);
    free_args(args, *argc);
    free(argc);

    return authenticated;
}

void begin_session(ATM *atm, char* user) {
    if (atm->session != NULL) {
        printf("A user is already logged in.\n");
        return;
    }
    if (strlen(user) == 0) {
        printf("Usage: begin-session <user-name>\n");
        return;
    }
    for (int i = 0; i < strlen(user); i++) {
        if (!isalpha(user[i])) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }
    }

    if (authenticate(atm, user)) {
        int attempts = get_attempts(atm->attempts, user);
        if (attempts > 5) {
            if (attempts > 10) {
                printf("This account is locked due to suspicious activity\n");
                return;
            }
            printf("This account will be locked after %d more failed log in attempts\n", (11 - attempts));
        }

        char* filetype = ".card";
        char filename[strlen(user) + strlen(filetype)];
        char buffer[250];
        FILE* card;

        memcpy(filename, user, strlen(user)+1);
        strcat(filename, filetype);

        card = fopen(filename, "r");

        if (card != NULL) {
            if (fgets(buffer, 250, card)) {
                if (send_card(atm, user, buffer)) {
                    char PIN[100];
                    printf("PIN? ");
                    fgets(PIN, 100, stdin);

                    if (PIN[4] != '\n') {
                        atm->attempts = failed_login_attempt(atm->attempts, user);
                        printf("Not authorized\n");
                    }
                    else {
                        PIN[4] = '\0';
                        if (send_pin(atm, user, PIN)) {
                            atm->session = malloc(250);
                            strcpy(atm->session, user);
                            printf("Authorized\n");
                        }
                        else {
                            atm->attempts = failed_login_attempt(atm->attempts, user);
                            printf("Not authorized\n");
                        }
                    }
                } else {
                    atm->attempts = failed_login_attempt(atm->attempts, user);
                    printf("Not authorized\n");
                }
            }
            else {
                printf("Unable to access %s's card\n", user);
            }
            fclose(card);
        }
        else {
            printf("Unable to access %s's card\n", user);
            char* response;
            response = bank_send_command(atm, "Unable to access card\n");
            free(response);
        }
    }
    else {
        printf("No such user\n");
    }
}
void atm_process_command(ATM *atm, char *command)
{
    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));

    parse(command, args, argc);

    // printf("argc: %d ", *argc);
    // for (int i = 0; i < *argc; i++) {
    //     printf(args[i]);
    //     printf(" ");
    // }

    if (strcmp(args[0], "begin-session") == 0) {
        begin_session(atm, args[1]);
    }
    else if (strcmp(args[0], "withdraw") == 0) {
        if (atm->session == NULL) {
            printf("No user logged in\n");
        }
        else if (strlen(args[1]) == 0) {
            printf("Usage: withdraw <amt>\n");
        }
        else if (atoi(args[1]) <= 0) {
            printf("Usage: withdraw <amt>\n");
        }
        else {
            char* send;
            char* response;

            char* sendargs[MAX_ARGS];
            for (int i = 0; i < 3; i++){
                sendargs[i] = malloc(1000);
            }
            strcpy(sendargs[0], args[0]);
            strcpy(sendargs[1], atm->session);
            strcpy(sendargs[2], args[1]);

            send = create_command(sendargs, 3);
            response = bank_send_command(atm, send);
            printf("%s", response);

            free_args(sendargs, 3);
            free(send);
            free(response);
        }
    }
    else if (strcmp(args[0], "balance") == 0) {
        if (atm->session == NULL) {
            printf("No user logged in\n");
        }
        else {
            char* send;
            char* response;

            char* sendargs[MAX_ARGS];
            for (int i = 0; i < 2; i++){
                sendargs[i] = malloc(1000);
            }
            strcpy(sendargs[0], args[0]);
            strcpy(sendargs[1], atm->session);

            send = create_command(sendargs, 2);
            response = bank_send_command(atm, send);
            printf("%s", response);

            free_args(sendargs, 2);
            free(send);
            free(response);
        }
    }
    else if (strcmp(args[0], "end-session") == 0) {
        if (atm->session == NULL) {
            printf("No user logged in\n");
        }
        else {
            free(atm->session);
            atm->session = NULL;
            printf("User logged out\n");
        }
    }
    else {
        printf("Invalid input\n");
    }

    free_args(args, *argc);
    free(argc);
}
