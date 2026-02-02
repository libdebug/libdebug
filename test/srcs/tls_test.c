//
// Test binary for TLS (Thread-Local Storage) symbol resolution
// This file tests various TLS scenarios and symbol types
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

// TLS variables with different initialization
__thread int tls_uninitialized;
__thread int tls_initialized = 42;
__thread char tls_string[64] = "Hello TLS";
__thread double tls_double = 3.14159;

// Regular global variables for comparison
int global_var = 100;
static int static_var = 200;

// Weak symbol
__attribute__((weak)) int weak_var = 999;

// Function to read TLS values
void read_tls_values(const char *thread_name) {
    printf("[%s] tls_uninitialized = %d (addr: %p)\n", 
           thread_name, tls_uninitialized, &tls_uninitialized);
    printf("[%s] tls_initialized = %d (addr: %p)\n", 
           thread_name, tls_initialized, &tls_initialized);
    printf("[%s] tls_string = \"%s\" (addr: %p)\n", 
           thread_name, tls_string, &tls_string);
    printf("[%s] tls_double = %f (addr: %p)\n", 
           thread_name, tls_double, &tls_double);
    printf("[%s] global_var = %d (addr: %p)\n", 
           thread_name, global_var, &global_var);
    fflush(stdout);
}

// Function to modify TLS values
void modify_tls_values(int base) {
    tls_uninitialized = base;
    tls_initialized = base + 1;
    tls_double = (double)base + 0.5;
    snprintf(tls_string, sizeof(tls_string), "Thread %d", base);
}

// Breakpoint target function
void breakpoint_here(void) {
    // This function exists solely as a breakpoint target
    asm volatile ("nop");
}

// Thread function
void *thread_func(void *arg) {
    int thread_num = *(int *)arg;
    
    // Modify TLS values for this thread
    modify_tls_values(thread_num * 100);
    
    // Breakpoint location
    breakpoint_here();
    
    // Read values
    char name[32];
    snprintf(name, sizeof(name), "Thread %d", thread_num);
    read_tls_values(name);
    
    // Wait a bit
    usleep(100000);
    
    return NULL;
}

// Function with local static (should appear in symbols)
int function_with_static(void) {
    static int call_count = 0;
    return ++call_count;
}

// Inline function (may or may not appear in symbols)
static inline int inline_function(int x) {
    return x * 2;
}

int main(int argc, char *argv[]) {
    pthread_t threads[3];
    int thread_nums[3] = {1, 2, 3};
    
    printf("Main thread starting\n");
    printf("Addresses of TLS variables (main thread):\n");
    printf("  &tls_uninitialized = %p\n", &tls_uninitialized);
    printf("  &tls_initialized = %p\n", &tls_initialized);
    printf("  &tls_string = %p\n", &tls_string);
    printf("  &tls_double = %p\n", &tls_double);
    printf("Global variables:\n");
    printf("  &global_var = %p\n", &global_var);
    printf("  &static_var = %p\n", &static_var);
    printf("  &weak_var = %p\n", &weak_var);
    fflush(stdout);
    
    // Initial breakpoint
    breakpoint_here();
    
    // Read initial values in main thread
    read_tls_values("Main");
    
    // Create threads
    for (int i = 0; i < 3; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, &thread_nums[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    
    // Modify main thread's TLS
    modify_tls_values(0);
    
    // Breakpoint after modification
    breakpoint_here();
    
    // Read modified values
    read_tls_values("Main (modified)");
    
    // Call functions to ensure they appear in symbols
    printf("function_with_static returned: %d\n", function_with_static());
    printf("inline_function(5) returned: %d\n", inline_function(5));
    
    // Wait for threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("All threads completed\n");
    
    // Final breakpoint
    breakpoint_here();
    
    return 0;
}
