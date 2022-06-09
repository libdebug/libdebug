#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAPPED_ADDRESS 0x1aabbcc1000
#define MAP_SIZE 0x1000
#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

int main(void){
    char *p = mmap((void *)MAPPED_ADDRESS, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (p == MAP_FAILED)
        handle_error("mmap");

    while(1){
        for (int i=0; i < MAP_SIZE; i++){
            p[i] = 0xff - (i%0x100);
        }
    }
}