/*
 * The ATM interfaces with the user.  User commands should be
 * handled by atm_process_command.
 *
 * The ATM can read .card files, but not .pin files.
 *
 * Feel free to update the struct and the processing as you desire
 * (though you probably won't need/want to change send/recv).
 */

#ifndef __ATM_H__
#define __ATM_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

typedef struct attempt_list
{
    char* user;
    int attempts;
    struct attempt_list* next;
} attempt_list;

struct attempt_list* failed_login_attempt(struct attempt_list* attempts, char* user);
int get_attempts(struct attempt_list* attempts, char* user);
void free_attempts(struct attempt_list* attempts);

typedef struct _ATM
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in atm_addr;

    // Protocol state
    char* session;
    struct attempt_list* attempts;
    unsigned char* key;
    unsigned char* iv;
} ATM;

ATM* atm_create(unsigned char* key, unsigned char* iv);
void atm_free(ATM *atm);
ssize_t atm_send(ATM *atm, unsigned char *data, size_t data_len);
ssize_t atm_recv(ATM *atm, unsigned char *data, size_t max_data_len);
void atm_process_command(ATM *atm, char *command);

#endif
