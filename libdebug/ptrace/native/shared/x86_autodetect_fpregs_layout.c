//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

// The purpose of this script is to detect the layout of the xsave area
// for the current CPU and dump it to a generated JSON file.

#include <cpuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define NT_X86_XSTATE 0x202

/* The extended state feature IDs in the state component bitmap.  */
#define X86_XSTATE_X87_ID	0
#define X86_XSTATE_SSE_ID	1
#define X86_XSTATE_AVX_ID	2
#define X86_XSTATE_BNDREGS_ID	3
#define X86_XSTATE_BNDCFG_ID	4
#define X86_XSTATE_K_ID		5
#define X86_XSTATE_ZMM_H_ID	6
#define X86_XSTATE_ZMM_ID	7
#define X86_XSTATE_PKRU_ID	9
#define X86_XSTATE_TILECFG_ID	17
#define X86_XSTATE_TILEDATA_ID	18
#define X86_XSTATE_APX_F_ID	19

int has_xsave()
{
    uint32_t eax, ebx, ecx, edx;

    __cpuid(0x0d, eax, ebx, ecx, edx);

    return eax & 0x1;
}

int xsave_element_offset(int element)
{
    uint32_t eax, ebx, ecx, edx;

    __cpuid_count(0xd, element, eax, ebx, ecx, edx);

    return ebx;
}

int xsave_element_size(int element)
{
    uint32_t eax, ebx, ecx, edx;

    __cpuid_count(0xd, element, eax, ebx, ecx, edx);

    return eax;
}

int xsave_area_size()
{
    uint32_t eax, ebx, ecx, edx;

    __cpuid_count(0xd, 0x0, eax, ebx, ecx, edx);

    return ebx;
}

int main(int argc, char *argv[])
{
    int pid = fork();

    int has_avx = 0, has_avx512 = 0;
    int has_xsave = 0;

    if (!pid) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            fprintf(stderr, "Failed to trace me\n");
            return 1;
        }

        raise(SIGSTOP);
    } else {
        if (waitpid(pid, NULL, 0) == -1) {
            fprintf(stderr, "Failed to wait for child\n");
            return 1;
        }
    }

    // dump a maximum size struct
    int *xsave_struct = malloc(4088);
    if (xsave_struct == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    struct iovec iov = {
        .iov_base = xsave_struct,
        .iov_len = 4088
    };

    int xcr0 = 0;

    // get the xsave area
    if (ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov) == -1) {
        fprintf(stderr, "Failed to get xsave area\n");

        // this probably means that the CPU (or kernel) doesn't support xsave
        // we can still get the fp regs through GETFPREGS
        has_avx = has_avx512 = has_xsave = 0;
    } else {
        // get xcr0
        xcr0 = xsave_struct[464 / 4];
        has_xsave = 1;
    }

    free(xsave_struct);

    // kill the child
    kill(pid, SIGKILL);

    // wait for the child to die
    if (waitpid(pid, NULL, 0) == -1) {
        fprintf(stderr, "Failed to wait for child\n");
        return 1;
    }

    puts("{");

    int current_size = 512;

    // if we have AVX
    if (xcr0 & (1 << X86_XSTATE_AVX_ID)) {
        int avx_offset = xsave_element_offset(X86_XSTATE_AVX_ID);
        int avx_size = xsave_element_size(X86_XSTATE_AVX_ID);
        if (avx_offset < current_size) {
            fprintf(stderr, "AVX offset is less than current size\n");
            return 1;
        }
        printf("    \"avx_ymm0_offset\": %d,\n", avx_offset);

        has_avx = 1;

        current_size = avx_offset + avx_size;
    }

    // if we have MPX
    if (xcr0 & (1 << X86_XSTATE_BNDREGS_ID)) {
        int mpx_offset = xsave_element_offset(X86_XSTATE_BNDREGS_ID);
        int mpx_size = xsave_element_size(X86_XSTATE_BNDREGS_ID);
        if (mpx_offset < current_size) {
            fprintf(stderr, "MPX offset is less than current size\n");
            return 1;
        }

        current_size = mpx_offset + mpx_size;
    }

    // if we have MPX
    if (xcr0 & (1 << X86_XSTATE_BNDCFG_ID)) {
        int mpx_offset = xsave_element_offset(X86_XSTATE_BNDCFG_ID);
        int mpx_size = xsave_element_size(X86_XSTATE_BNDCFG_ID);
        if (mpx_offset < current_size) {
            fprintf(stderr, "MPX offset is less than current size\n");
            return 1;
        }

        current_size = mpx_offset + mpx_size;
    }

    // if we have AVX-512
    if (xcr0 & (1 << X86_XSTATE_K_ID)) {
        int avx512_offset = xsave_element_offset(X86_XSTATE_K_ID);
        int avx512_size = xsave_element_size(X86_XSTATE_K_ID);
        if (avx512_offset < current_size) {
            fprintf(stderr, "AVX-512 offset is less than current size\n");
            return 1;
        }

        current_size = avx512_offset + avx512_size;
    }

    // if we have AVX-512
    if (xcr0 & (1 << X86_XSTATE_ZMM_H_ID)) {
        int avx512_offset = xsave_element_offset(X86_XSTATE_ZMM_H_ID);
        int avx512_size = xsave_element_size(X86_XSTATE_ZMM_H_ID);
        if (avx512_offset < current_size) {
            fprintf(stderr, "AVX-512 offset is less than current size\n");
            return 1;
        }
        printf("    \"avx512_zmm0_offset\": %d,\n", avx512_offset);

        current_size = avx512_offset + avx512_size;
    }

    // if we have AVX-512
    if (xcr0 & (1 << X86_XSTATE_ZMM_ID)) {
        int avx512_offset = xsave_element_offset(X86_XSTATE_ZMM_ID);
        int avx512_size = xsave_element_size(X86_XSTATE_ZMM_ID);
        if (avx512_offset < current_size) {
            fprintf(stderr, "AVX-512 offset is less than current size\n");
            return 1;
        }
        printf("    \"avx512_zmm1_offset\": %d,\n", avx512_offset);

        has_avx512 = 1;

        current_size = avx512_offset + avx512_size;
    }

    // If we have PKRU
    if (xcr0 & (1 << X86_XSTATE_PKRU_ID)) {
        int pkru_offset = xsave_element_offset(X86_XSTATE_PKRU_ID);
        int pkru_size = xsave_element_size(X86_XSTATE_PKRU_ID);
        if (pkru_offset < current_size) {
            fprintf(stderr, "PKRU offset is less than current size\n");
            return 1;
        }

        current_size = pkru_offset + pkru_size;
    }

    if (has_xsave) {
        size_t xsave_size = xsave_area_size();
        printf("    \"struct_size\": %d,\n", xsave_size > current_size ? xsave_size : current_size);
        printf("    \"has_xsave\": true,\n");
    } else {
        // If we don't have xsave, we assume the size is 512 bytes
        printf("    \"struct_size\": %d,\n", current_size);
        printf("    \"has_xsave\": false,\n");
    }

    if (!has_avx && !has_avx512) {
        puts("    \"type\": 0");
    } else if (has_avx && !has_avx512) {
        puts("    \"type\": 1");
    } else if (has_avx && has_avx512) {
        puts("    \"type\": 2");
    } else {
        fprintf(stderr, "Bad state detected!\n");
        return 1;
    }

    puts("}");

    return 0;
}
