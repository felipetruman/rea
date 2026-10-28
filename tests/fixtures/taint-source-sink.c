#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_sink(char *user_input) {
    char command[256];
    snprintf(command, sizeof(command), "echo %s", user_input);
    system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    vulnerable_sink(argv[1]);
    return 0;
}
