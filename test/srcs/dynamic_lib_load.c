//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(void) {
    void *handle;
    double (*cosine)(double);
    char *error;

    // Open libm dynamically
    handle = dlopen("libm.so.6", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    // Clear any existing errors
    dlerror();

    // Load symbol for cos()
    *(void **)(&cosine) = dlsym(handle, "cos");

    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "dlsym failed: %s\n", error);
        dlclose(handle);
        exit(EXIT_FAILURE);
    }

    // Call cos(2.0)
    printf("cos(2.0) = %f\n", (*cosine)(2.0));

    // Close the library
    dlclose(handle);
    return 0;
}
