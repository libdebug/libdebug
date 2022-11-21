#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define MAPPED_ADDRESS_T1 0x1aabbcc1000
#define MAPPED_ADDRESS_T2 0x2aabbcc1000
#define MAP_SIZE 0x1000
#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)


void *read_thread_t1(void *vargp)
{
    char *p = mmap((void *)MAPPED_ADDRESS_T1, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (p == MAP_FAILED)
        handle_error("mmap");

    while(1){
        for (int i=0; i < MAP_SIZE; i++){
            p[i] = 0xff - (i%0x100);
        }
    }
}

void *read_thread_t2(void *vargp)
{
    char *p = mmap((void *)MAPPED_ADDRESS_T2, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (p == MAP_FAILED)
        handle_error("mmap");

    while(1){
        for (int i=0; i < MAP_SIZE; i++){
            p[i] = 0xff - (i%0x100);
        }
    }
}

int main(void){
    pthread_t tid1, tid2;
    pthread_create(&tid1, NULL, read_thread_t1, NULL);
    pthread_create(&tid2, NULL, read_thread_t2, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
}