#include <stdio.h>
#include <stdlib.h>

void random_function()
{
    printf("Random function\n");

    int x;
    for (int i = 0; i < 10; i++)
    {
        x += i;        
    }

    printf("x = %d\n", x);
}

int main()
{
    printf("Provola\n");

    random_function();

    return EXIT_SUCCESS;
}
