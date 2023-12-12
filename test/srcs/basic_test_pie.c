#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t register_test(uint64_t number)
{
    return number;
}

int main()
{
    uint64_t value;

    value = 0xaabbccdd11223344;

    value = register_test(value);

    printf("Basic test pie: %lx\n", value);

    return 0;
}
