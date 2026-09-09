#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern int container_value(void);
extern char **environ;
volatile int marker = 42;

__attribute__((noinline)) void checkpoint(void) {
    __asm__ volatile("nop");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    if (argc > 1 && strcmp(argv[1], "environment") == 0) {
        for (char **entry = environ; *entry; ++entry) fwrite(*entry, 1, strlen(*entry) + 1, stdout);
        puts("ENV-END");
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "output") == 0) {
        char output[4096], error[4096];
        memset(output, 'O', sizeof(output));
        memset(error, 'E', sizeof(error));
        for (int count = atoi(argv[2]); count > 0; count -= sizeof(output)) {
            fwrite(output, 1, sizeof(output), stdout);
            fwrite(error, 1, sizeof(error), stderr);
        }
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "orphan") == 0) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (child > 0) { checkpoint(); return 0; }
        puts("child-ready");
        char line[128];
        if (!fgets(line, sizeof(line), stdin)) return 1;
        puts("child-done");
        return 0;
    }
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
