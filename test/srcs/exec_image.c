#include <stdio.h>
#include <unistd.h>
#define STR_(x) #x
#define STR(x) STR_(x)
__attribute__((section(".probe"), naked, noinline)) int probe(void) {
    __asm__("mov $" STR(IMAGE) ", %eax; "
            ".global probe_return; probe_return: ret; nop; nop; nop; nop");
}
int main(int argc, char **argv) {
    if (argc > 1) { execl(argv[1], argv[1], NULL); return 2; }
    int value = probe();
    printf("IMAGE %d\n", value);
    return value == IMAGE ? 0 : 3;
}
