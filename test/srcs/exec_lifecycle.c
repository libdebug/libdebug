#include <stdio.h>

__attribute__((noinline)) void checkpoint(void) {
    __asm__ volatile("" ::: "memory");
}

int main(void) {
    checkpoint();
    puts("DONE");
    return 0;
}
