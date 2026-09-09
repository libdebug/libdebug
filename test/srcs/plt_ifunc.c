#include <stdio.h>

static int implementation(void) { return 42; }
static int (*resolve_local(void))(void) { return implementation; }
int local_ifunc(void) __attribute__((ifunc("resolve_local")));

int main(void)
{
    puts("before ifunc");
    int value = local_ifunc();
    printf("after ifunc: %d\n", value);
    return value != 42;
}
