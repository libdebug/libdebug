#include <stdio.h>

int main(void)
{
    int (*volatile output)(const char *) = puts;
    int (*volatile format)(const char *, ...) = printf;
    puts("multiple GOT stubs");
    printf("result: %d\n", 42);
    return output == 0 || format == 0;
}
