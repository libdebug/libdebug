#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f(int i)
{
    (void) i;
}

int main()
{
    for (int i = 0; i < 1e5; i++) {
        f(i);
    }

    return 0;
}