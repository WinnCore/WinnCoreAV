#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    // Suspicious patterns for detection
    system("/bin/sh");
    execve("/bin/bash", NULL, NULL);
    printf("Suspicious behavior\n");
    return 0;
}
