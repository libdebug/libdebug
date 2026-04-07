/*
 * Compile with:
 *   aarch64-linux-gnu-gcc -march=armv8.3-a -mbranch-protection=pac-ret+bti \
 *       -O1 -nostdlib -o pac_test pac_test.c
 */

volatile int sink;

__attribute__((noinline, target("branch-protection=pac-ret+bti")))
int deep_func(int x) {
    sink = x;
    return sink + 1;
}

__attribute__((noinline, target("branch-protection=pac-ret+bti")))
int middle_func(int x) {
    return deep_func(x) + deep_func(x + 1);
}

__attribute__((noinline, target("branch-protection=pac-ret+bti")))
int outer_func(int x) {
    return middle_func(x) + middle_func(x * 2);
}

void _start(void) {
    outer_func(42);
    __asm__ volatile(
        "mov x0, #0\n"
        "mov x8, #93\n"
        "svc #0\n"
    );
}
