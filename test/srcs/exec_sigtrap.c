#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t received;
static void trap(int signal, siginfo_t *info, void *context) {
    received++;
}
__attribute__((noinline)) void checkpoint(void) {
    __asm__ volatile("nop; nop" ::: "memory");
}
int main(int argc, char **argv) {
    struct sigaction action = {.sa_sigaction = trap, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, NULL)) return 2;
    checkpoint();
    if (!strcmp(argv[1], "kill")) kill(getpid(), SIGTRAP);
    else if (!strcmp(argv[1], "raise")) raise(SIGTRAP);
    else { union sigval value = {.sival_int = 42}; sigqueue(getpid(), SIGTRAP, value); }
    printf("HANDLED %d\n", received);
    return received == 1 ? 0 : 3;
}
