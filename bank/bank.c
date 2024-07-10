#include "bank.h"
#include "parse/parse.h"
#include "ports.h"
#include "encryption.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <limits.h>
#include "../util/list.h"
#include "../util/list.c"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <time.h>


Bank* bank_create(unsigned char key[32], unsigned char iv[16])
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    } 

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    
    List *pins = list_create();
    List *card_nums = list_create();
    List *balances = list_create();

    bank->pins = pins;
    bank->card_nums = card_nums;
    bank->balances = balances;

    bank->key = malloc(32);
    bank->iv = malloc(16);

    memcpy(bank->key, key, 32);
    memcpy(bank->iv, iv, 16);

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, unsigned char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, unsigned char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_send_response(Bank *bank, char *response) {
    unsigned char ciphertext[128];
    int ciphertext_len;

    ciphertext_len = encrypt((unsigned char*)response, strlen(response), bank->key, bank->iv, ciphertext);

    //printf("response: %s\n", ciphertext);

    bank_send(bank, ciphertext, ciphertext_len);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));

    parse(command, args, argc);

    char valid_cmds[3][12]= {"create-user","deposit","balance"};
     
    if (strcmp(args[0], valid_cmds[0]) == 0){ // create-user cmd
        create_user(bank, args, *argc);

    } else if (strcmp(args[0], valid_cmds[1]) == 0){ // deposit cmd
        deposit(bank, args, *argc);

    } else if (strcmp(args[0], valid_cmds[2]) == 0) { // balance cmd
        balance(bank, args, *argc);

    } else {
        printf("Invalid command\n");
    }

    free_args(args, *argc);
    free(argc);
}

void bank_process_remote_command(Bank *bank, unsigned char *ciphertext, size_t len)
{
    //printf("ciphertext: %s\n", ciphertext);

    //int decryptedtext_len;
    char* command = malloc(1000);

    /* Decrypt the ciphertext */
    decrypt(ciphertext, len, bank->key, bank->iv,
                                (unsigned char*) command);

    //printf("plaintext: %s", command);

    char* args[MAX_ARGS];
    int* argc = malloc(sizeof(int*));

    parse(command, args, argc);

    char valid_cmds[5][13]= {"authenticate","card","pin","balance","withdraw"};
    
    if (strcmp(args[0], valid_cmds[0]) == 0){ // authenticate
        atm_authenticate(bank, args, *argc);
    } else if (strcmp(args[0], valid_cmds[1]) == 0) { // card
        atm_card(bank, args, *argc);
    } else if (strcmp(args[0], valid_cmds[2]) == 0) { // pin
        atm_pin(bank, args, *argc);
    } else if (strcmp(args[0], valid_cmds[3]) == 0) { // balance
        atm_balance(bank, args, *argc);
    } else if (strcmp(args[0], valid_cmds[4]) == 0) { // withdraw
        atm_withdraw(bank, args, *argc);
    } else {
        atm_send_response(bank, "Invalid command\n");
    }

    free_args(args, *argc);
    free(argc);
}

void create_user(Bank *bank, char *args[MAX_ARGS], int num_args) {
    if (num_args != 4) {
        printf("Usage: create-user <user-name> <pin> <balance>\n");
        return;
    }

    regex_t pin_regex;
    regex_t usr_regex;
    regex_t bal_regex;

    int usr_comp = regcomp(&usr_regex, "^[a-zA-Z]\\{1,250\\}$", 0);
    int pin_comp = regcomp(&pin_regex, "^[0-9][0-9][0-9][0-9]$", 0);
    int bal_comp = regcomp(&bal_regex, "^[0-9]\\+$", 0);

    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    int pin_status = regexec(&pin_regex, args[2], (size_t) 0, NULL, 0);
    int bal_status = regexec(&bal_regex, args[3], (size_t) 0, NULL, 0);
     
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);
    // printf("pin: %d %d %s\n", pin_comp, pin_status, args[2]);
    // printf("bal: %d %d %s\n", bal_comp, bal_status, args[3]);

    int bal_test = atoi(args[3]);
    char bal_temp[20];
    snprintf(bal_temp, 20, "%d", bal_test);
    int valid_bal = strcmp(args[3], bal_temp);

    if (usr_comp == 0 && pin_comp == 0 && bal_comp == 0 && bal_status == 0 && usr_status == 0 && pin_status == 0 && valid_bal == 0){
        char *usr = NULL;
        int usr_len = strlen(args[1]) + 1;
        usr = malloc(usr_len * sizeof(char));
        if (usr == NULL) {  // checks if memory was allocated
            printf("Cannot allocate %d bytes for string\n", usr_len+1);
            exit(EXIT_FAILURE);
        }
        strncpy(usr, args[1], usr_len);
        if (list_find(bank->pins, usr) == NULL) {
            int pin = atoi(args[2]);
            int bal = atoi(args[3]);
           
            list_add(bank->balances, usr, bal);
            list_add(bank->pins, usr, pin);

            // list_add(bank->card_nums, user_name, ???);      //ADD CARD NUMBER INFO
            
            char file_name[300]= "./";
            strcat(file_name, usr);
            strcat(file_name, ".card");

            unsigned int outLen = SHA256_DIGEST_LENGTH ;
            const unsigned char message[261] = {0}; // 250 input + 10 bit random str
            const unsigned char rndmstr[10] = {0};
            srand(time(NULL)); 
            rand_str(rndmstr, 10);
            list_add(bank->card_nums, usr, rndmstr);

            strncpy((char *)rndmstr, usr, 10*sizeof(char)); 
            strncat(message,usr,250*sizeof(char));
            //unsigned char **digest = (unsigned char **) malloc(SHA256_DIGEST_LENGTH*sizeof(char));
            //strncpy((char *)message, usr, 250*sizeof(char)); 
            // Initialization, should only be called once.
        

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, message, 250);
            SHA256_Final(hash, &sha256);

            unlink(file_name);

            for (int i = 0; i < 32; i++) {
                if (hash[i] < 33) {
                    hash[i] = hash[i] + 33;
                }
            }

            FILE *fp; 
            fp = fopen(file_name,"wb");
            if ( fp != NULL) {
                    fwrite(hash, sizeof hash[0], outLen, fp);
                    fclose(fp);
                    if (ferror(fp)) {
                        printf("Error creating card file for user %s\n", args[1]);
                        list_del(bank->balances, usr); 
                        list_del(bank->pins, usr);
                        list_del(bank->card_nums, usr);
                    } else {
                        printf("Created user %s\n", args[1]);
                    } 
            } else {
                    printf("Error creating card file for user %s\n", args[1]);
                    list_del(bank->balances, usr);
                    list_del(bank->pins, usr);
                    list_del(bank->card_nums, usr);
            }
        } else {
            printf("Error: user %s already exists\n", args[1]);
        }
    } else {
        printf("Usage: create-user <user-name> <pin> <balance>\n");
    }
}
void deposit(Bank *bank, char *args[MAX_ARGS],int num_args) {
    if (num_args != 3) {
        printf("Usage: deposit <user-name> <amt>\n");
        return;
    }

    regex_t usr_regex;
    regex_t amt_regex;
    
    int usr_comp = regcomp(&usr_regex, "^[a-zA-Z]\\{1,250\\}$",0);
    int amt_comp = regcomp(&amt_regex, "^[0-9]\\+$",0);

    int usr_status = regexec(&usr_regex,args[1], (size_t) 0, NULL, 0);
    int amt_status = regexec(&amt_regex, args[2], (size_t) 0, NULL, 0);

    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);
    // printf("amt: %d %d %s\n", amt_comp, amt_status, args[2]);

    int amt_test = atoi(args[2]);
    char amt_temp[20];
    snprintf(amt_temp, 20, "%d", amt_test);
    int valid_amt = strcmp(args[2], amt_temp);
       
    if (usr_comp == 0 && amt_comp == 0 && usr_status == 0 && amt_status == 0, valid_amt == 0){

        char *usr = args[1];

        if (list_find(bank->balances, usr) == NULL) {
            printf("No such user\n");
        } else {

            int amt = atoi(args[2]); 
            int curr_bal = (int) list_find(bank->balances, usr);
            int diff = INT_MAX - curr_bal;

            if (amt > diff) {
                printf("Too rich for this program\n");
            } else {
                int new_bal = amt + curr_bal;

                list_del(bank->balances, usr);

                char *new_usr = NULL;
                int usr_len = strlen(args[1])+1;
                new_usr = malloc(usr_len * sizeof(char));
                if (new_usr == NULL) {  // checks if memory was allocated
                    printf("Cannot allocate %d bytes for string\n", usr_len+1);
                    exit(EXIT_FAILURE);
                }
                strncpy(new_usr, args[1], usr_len);

                list_add(bank->balances, new_usr, new_bal);
                printf("$%d added to %s's account\n", amt, args[1]);
            }
        }
    } else {
        printf("Usage: deposit <user-name> <amt>\n");
    }
}
void balance(Bank *bank, char *args[MAX_ARGS], int num_args) {
    if (num_args != 2) {
        printf("Usage: balance <user>\n");
        return;
    }

    regex_t usr_regex;
    int usr_comp =  regcomp(&usr_regex,"^[a-zA-Z]\\{1,250\\}$",0);
    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);

    // printf("list size: %u\n", list_size(bank->balances));

    if (usr_comp == 0 && usr_status == 0){
        if (list_find(bank->balances, args[1]) == NULL) {
            printf("No such user\n");
        } else {
            printf("$%d\n", list_find(bank->balances, args[1]));
        }
    } else {
        printf("Usage: balance <user>\n");
    }
}

void atm_authenticate(Bank *bank, char *args[MAX_ARGS], int num_args) {
    char sendline[1000];

    if (num_args != 2) {
        sprintf(sendline, "Bank error (authenticate)\n");
        atm_send_response(bank, sendline);
        return;
    }

    regex_t usr_regex;
    int usr_comp =  regcomp(&usr_regex,"^[a-zA-Z]\\{1,250\\}$",0);
    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);

    // printf("list size: %u\n", list_size(bank->balances));

    if (usr_comp == 0 && usr_status == 0){
        if (list_find(bank->balances, args[1]) == NULL) {
            sprintf(sendline, "No such user\n");
            atm_send_response(bank, sendline);
        } else {
            sprintf(sendline, "%s authenticated\n", args[1]);
            atm_send_response(bank, sendline);
        }
    } else {
        sprintf(sendline, "Bank error (authenticate)\n");
        atm_send_response(bank, sendline);
    }
}

void atm_card(Bank *bank, char *args[MAX_ARGS], int num_args) {
    char sendline[1000];

    if (num_args != 3) {
        sprintf(sendline, "Bank error (card)\n");
        atm_send_response(bank, sendline);
        return;
    }

    regex_t usr_regex;
    int usr_comp =  regcomp(&usr_regex,"^[a-zA-Z]\\{1,250\\}$",0);
    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);

    // printf("list size: %u\n", list_size(bank->balances));

    if (usr_comp == 0 && usr_status == 0){
        if (list_find(bank->balances, args[1]) == NULL) {
            sprintf(sendline, "No such user\n");
            atm_send_response(bank, sendline);
        } else {
            if (validate_user_card(bank,args[1],args[2]) == 0) {
                sprintf(sendline, "%s %s match\n", args[1], args[2]);
                atm_send_response(bank, sendline);
            }
            else {
                sprintf(sendline, "Not authorized\n");
                atm_send_response(bank, sendline);
            }
        }
    } else {
        sprintf(sendline, "Bank error (card)\n");
        atm_send_response(bank, sendline);
    }
}

void atm_pin(Bank *bank, char *args[MAX_ARGS], int num_args) {
    char sendline[1000];

    if (num_args != 3) {
        sprintf(sendline, "Bank error (pin)\n");
        atm_send_response(bank, sendline);
        return;
    }

    regex_t usr_regex;
    int usr_comp =  regcomp(&usr_regex,"^[a-zA-Z]\\{1,250\\}$",0);
    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);

    // printf("list size: %u\n", list_size(bank->pins));

    if (usr_comp == 0 && usr_status == 0){
        if (list_find(bank->pins, args[1]) == NULL) {
            sprintf(sendline, "No such user\n");
            atm_send_response(bank, sendline);
        } else {
            if (list_find(bank->pins, args[1]) == atoi(args[2])) {
                sprintf(sendline, "%s %s correct\n", args[1], args[2]);
                atm_send_response(bank, sendline);
            }
            else {
                sprintf(sendline, "Not authorized\n");
                atm_send_response(bank, sendline);
            }
        }
    } else {
        sprintf(sendline, "Bank error (pin)\n");
        atm_send_response(bank, sendline);
    }
}

void atm_balance(Bank *bank, char *args[MAX_ARGS], int num_args) {
    char sendline[1000];

    if (num_args != 2) {
        sprintf(sendline, "Bank error (balance)\n");
        atm_send_response(bank, sendline);
        return;
    }

    regex_t usr_regex;
    int usr_comp =  regcomp(&usr_regex,"^[a-zA-Z]\\{1,250\\}$",0);
    int usr_status = regexec(&usr_regex, args[1], (size_t) 0, NULL, 0);
    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);

    // printf("list size: %u\n", list_size(bank->balances));
    if (usr_comp == 0 && usr_status == 0){
        if (list_find(bank->balances, args[1]) == NULL) {
            sprintf(sendline, "No such user\n");
            atm_send_response(bank, sendline);
        } else {
            sprintf(sendline, "$%d\n", list_find(bank->balances, args[1]));
            atm_send_response(bank, sendline);
        }
    } else {
        sprintf(sendline, "Bank error (balance)\n");
        atm_send_response(bank, sendline);
    }
}

void atm_withdraw(Bank *bank, char *args[MAX_ARGS], int num_args) {
    char sendline[1000];

    if (num_args != 3) {
        sprintf(sendline, "Bank error (withdraw)\n");
        atm_send_response(bank, sendline);
        return;
    }

    if (num_args != 3) {
        return;
    }

    regex_t usr_regex;
    regex_t amt_regex;
    
    int usr_comp = regcomp(&usr_regex, "^[a-zA-Z]\\{1,250\\}$",0);
    int amt_comp = regcomp(&amt_regex, "^[0-9]\\+$",0);

    int usr_status = regexec(&usr_regex,args[1], (size_t) 0, NULL, 0);
    int amt_status = regexec(&amt_regex, args[2], (size_t) 0, NULL, 0);

    // printf("usr: %d %d %s\n", usr_comp, usr_status, args[1]);
    // printf("amt: %d %d %s\n", amt_comp, amt_status, args[2]);

    int amt_test = atoi(args[2]);
    char amt_temp[20];
    snprintf(amt_temp, 20, "%d", amt_test);
    int valid_amt = strcmp(args[2], amt_temp);
       
    if (usr_comp == 0 && amt_comp == 0 && usr_status == 0 && amt_status == 0 && valid_amt == 0){

        char *usr = args[1];

        if (list_find(bank->balances, usr) == NULL) {
            sprintf(sendline, "No such user\n");
            atm_send_response(bank, sendline);
        } else {

            int amt = atoi(args[2]); 
            int curr_bal = (int) list_find(bank->balances, usr);

            if (amt > curr_bal) {
                sprintf(sendline, "Insufficient funds\n");
                atm_send_response(bank, sendline);
            } else {
                int new_bal = curr_bal - amt;

                list_del(bank->balances, usr);      // does this free the old usr?

                char *new_usr = NULL;
                int usr_len = strlen(args[1])+1;
                new_usr = malloc(usr_len * sizeof(char));
                if (new_usr == NULL) {  // checks if memory was allocated
                    sprintf(sendline, "Cannot allocate %zu bytes for string\n", usr_len+1);
                    atm_send_response(bank, sendline);
                    printf("Cannot allocate %zu bytes for string\n", usr_len+1);
                    exit(EXIT_FAILURE);
                }
                strncpy(new_usr, args[1], usr_len);

                list_add(bank->balances, new_usr, new_bal);
                sprintf(sendline, "$%d dispensed\n", amt);
                atm_send_response(bank, sendline);
            }
        }
    } else {
        sprintf(sendline, "Bank error (withdraw)\n");
        atm_send_response(bank, sendline);
    }
}

int validate_user_card(Bank *bank, char * usr, char * card_data) {
    if (list_find(bank->pins, usr) == NULL || list_find(bank->pins, usr) == NULL) {
        return 0;
    }

    unsigned int outLen = SHA256_DIGEST_LENGTH;
    const unsigned char message[261] = {0}; 
    unsigned char * rndmstr = (unsigned char *)list_find(bank->card_nums, usr);
    strncpy((char *)rndmstr, usr, 10*sizeof(char)); 
    strncat((char *)message, usr, 250*sizeof(char)); 
    

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, 250);
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < 32; i++) {
        if (hash[i] < 33) {
            hash[i] = hash[i] + 33;
        }
    }

    /*
    printf("Digest is: ");
            for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", hash[i]);
            printf("\n");
    */
    unsigned char buffer[SHA256_DIGEST_LENGTH] = {0};
    strncpy((char *)buffer, card_data, SHA256_DIGEST_LENGTH*sizeof(char)); 
    

    int cmp =  memcmp(buffer, hash, SHA256_DIGEST_LENGTH); 
    return cmp;
}

void rand_str(unsigned char *dest, size_t length) {
    unsigned char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}