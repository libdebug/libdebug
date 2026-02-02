//
// Test binary for symbol types, versioning, and special symbols
// This file tests various ELF symbol scenarios
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// Regular global variable (OBJECT, GLOBAL)
int global_data = 42;

// Uninitialized global (OBJECT, GLOBAL, in .bss)
int global_bss;

// Static global (OBJECT, LOCAL)
static int static_data = 123;

// Weak symbol (can be overridden)
__attribute__((weak)) int weak_symbol = 999;

// Weak function
__attribute__((weak)) void weak_function(void) {
    printf("Default weak_function\n");
}

// Hidden symbol (not exported)
__attribute__((visibility("hidden"))) int hidden_var = 777;

// Protected symbol
__attribute__((visibility("protected"))) int protected_var = 888;

// Array (OBJECT)
int data_array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

// String constant
const char *string_data = "Test string constant";

// Function pointer
typedef int (*func_ptr_t)(int);

// Simple functions
int simple_function(int x) {
    return x * 2;
}

static int static_function(int x) {
    return x * 3;
}

// Function that will be called through PLT
int plt_example(void) {
    // These libc functions go through PLT
    char *s = malloc(100);
    if (s) {
        strcpy(s, "PLT example");
        printf("%s\n", s);
        free(s);
    }
    return 0;
}

// Constructor function
__attribute__((constructor)) void init_function(void) {
    printf("Constructor called\n");
}

// Destructor function  
__attribute__((destructor)) void fini_function(void) {
    printf("Destructor called\n");
}

// Breakpoint targets at different locations
void breakpoint_start(void) { asm volatile("nop"); }
void breakpoint_middle(void) { asm volatile("nop"); }
void breakpoint_end(void) { asm volatile("nop"); }

// Function with known prologue/epilogue
int function_with_frame(int a, int b, int c) {
    int local1 = a + b;
    int local2 = b + c;
    int local3 = local1 + local2;
    
    breakpoint_middle();
    
    return local3;
}

// Variadic function
int variadic_function(int count, ...) {
    return count;
}

// Recursive function
int recursive_function(int n) {
    if (n <= 1) return 1;
    return n * recursive_function(n - 1);
}

// Function that uses dlsym
void *get_symbol_address(const char *name) {
    void *handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) return NULL;
    void *addr = dlsym(handle, name);
    dlclose(handle);
    return addr;
}

int main(int argc, char *argv[]) {
    printf("Symbol types test starting\n");
    printf("\n=== Symbol Addresses ===\n");
    
    // Print addresses of various symbols
    printf("Functions:\n");
    printf("  main = %p\n", (void*)main);
    printf("  simple_function = %p\n", (void*)simple_function);
    printf("  static_function = %p\n", (void*)static_function);
    printf("  weak_function = %p\n", (void*)weak_function);
    printf("  function_with_frame = %p\n", (void*)function_with_frame);
    printf("  breakpoint_start = %p\n", (void*)breakpoint_start);
    printf("  breakpoint_middle = %p\n", (void*)breakpoint_middle);
    printf("  breakpoint_end = %p\n", (void*)breakpoint_end);
    
    printf("\nGlobal data:\n");
    printf("  global_data = %p (value: %d)\n", (void*)&global_data, global_data);
    printf("  global_bss = %p (value: %d)\n", (void*)&global_bss, global_bss);
    printf("  static_data = %p (value: %d)\n", (void*)&static_data, static_data);
    printf("  weak_symbol = %p (value: %d)\n", (void*)&weak_symbol, weak_symbol);
    printf("  hidden_var = %p (value: %d)\n", (void*)&hidden_var, hidden_var);
    printf("  protected_var = %p (value: %d)\n", (void*)&protected_var, protected_var);
    printf("  data_array = %p\n", (void*)data_array);
    printf("  string_data = %p\n", (void*)string_data);
    
    fflush(stdout);
    
    // First breakpoint
    breakpoint_start();
    
    // Call various functions
    int result = 0;
    result += simple_function(10);
    result += static_function(20);
    result += function_with_frame(1, 2, 3);
    result += recursive_function(5);
    
    weak_function();
    
    // PLT calls
    plt_example();
    
    // Look up a symbol dynamically
    void *sym_addr = get_symbol_address("simple_function");
    printf("\ndlsym found simple_function at: %p\n", sym_addr);
    
    // Use variadic function
    result += variadic_function(3, 1, 2, 3);
    
    printf("\nTotal result: %d\n", result);
    
    // Final breakpoint
    breakpoint_end();
    
    return 0;
}
