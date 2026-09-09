#include <stdio.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void checkpoint(void) { __asm__ volatile("nop" ::: "memory"); }
int main(int argc, char **argv) {
    if (setpgid(0, getpgid(getppid())) < 0) return 2;
    if (!strcmp(argv[1], "session") && setsid() < 0) return 3;
    puts("CHANGED");
    fflush(stdout);
    usleep(20000);
    checkpoint();
    return 0;
}
