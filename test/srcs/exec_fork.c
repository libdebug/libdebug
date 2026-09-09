#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) return 0;
    waitpid(child, 0, 0);
    return 0;
}
