#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *strings[] = {"0Test string number 0", "1Test string number 1", "2Test string number 2", "3Test string number 3"};



int main(void){
    int i=0;
    while (1){
        puts(strings[i]);
        i = (i+1) % 4;
        usleep(100);
    }

}