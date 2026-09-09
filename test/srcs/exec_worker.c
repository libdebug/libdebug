#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((noinline)) void unused(void) { __asm__ volatile("nop; nop"); }
static void *idle(void *arg) { for (;;) pause(); return NULL; }
static void *execute(void *path) {
    puts("WORKER EXEC"); fflush(stdout);
    execl(path, path, NULL);
    _exit(2);
}
int main(int argc, char **argv) {
    pthread_t workers[8], worker;
    for (int i = 0; i < atoi(argv[2]); ++i)
        if (pthread_create(&workers[i], NULL, idle, NULL)) return 3;
    if (pthread_create(&worker, NULL, execute, argv[1])) return 4;
    pthread_join(worker, NULL);
    return 5;
}
