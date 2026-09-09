#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern int container_value(void);
volatile int marker = 42;

__attribute__((noinline)) void checkpoint(void) {
    __asm__ volatile("nop");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    if (argc > 1 && strcmp(argv[1], "fork") == 0) {
        pid_t child = fork();
        if (child < 0) return 1;
        checkpoint();
        printf("%s\n", child == 0 ? "child" : "parent");
        if (child > 0) waitpid(child, NULL, 0);
        return 0;
    }
    checkpoint();
    printf("argv0=%s\n", argv[0]);
    printf("arg=%s\n", argc > 1 ? argv[1] : "none");
    printf("env=%s\n", getenv("LIBDEBUG_FIXTURE") ?: "unset");
    printf("extra=%s\n", getenv("LIBDEBUG_EXTRA") ?: "unset");
    printf("value=%d\n", container_value());
    fprintf(stderr, "stderr-ready\n");
    char line[128];
    if (fgets(line, sizeof(line), stdin)) printf("echo=%s", line);
    return 0;
}
