#include <stdio.h>

int main(int argc, char** argv) {
    char buffer[32];
    
    // Setvbuf is used to disable buffering
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    printf("libdebug 4 exploitation testing bench\n");

    printf("Enter a string: ");
    // This is a vulnerable function, it does not check the size of the input
    gets(buffer);

    return 0;
}