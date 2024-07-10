/*
 * Parses arguments from a command string. Arguments are seperated by whitespace.
 */

const int MAX_ARGS;

void parse(char* command, char* args[MAX_ARGS], int* argc);
void free_args(char** args, int count);