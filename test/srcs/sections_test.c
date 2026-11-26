//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdint.h>

/* -----------------------------
 * Common/text/rodata/data/bss
 * ----------------------------- */

/* .text (default code) */
int add(int a, int b) { return a + b; }

/* .rodata (const data) */
static const char hello_msg[] = "hello from .rodata";

/* .data (writable, initialized) */
int global_counter = 42;

/* .bss (writable, zero-initialized) */
int big_buffer[1024]; /* should land in .bss */

/* -----------------------------
 * TLS (.tdata / .tbss)
 * ----------------------------- */
#if defined(__GNUC__) || defined(__clang__)
__thread int tls_initialized = 7;   /* .tdata */
__thread int tls_uninitialized;     /* .tbss */
#endif

/* ----------------------------------------
 * Hot/Cold split text (.text.hot / .text.unlikely)
 * ---------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static int hot_path(int x) { return x * 3; }

#if defined(__GNUC__) || defined(__clang__)
__attribute__((cold))
#endif
static void cold_path(const char* why) {
    if (why) fprintf(stderr, "Cold path: %s\n", why);
}

/* ----------------------------------------
 * Custom sections via attributes
 * ---------------------------------------- */

/* Keep from being GC'd: used; add alignment to test sh_addralign parsing */
#if defined(__GNUC__) || defined(__clang__)
#define USED   __attribute__((used))
#define SEC(x) __attribute__((section(x)))
#define ALN(n) __attribute__((aligned(n)))
#else
#define USED
#define SEC(x)
#define ALN(n)
#endif

/* Custom read-only section */
static const char custom_ro[] SEC(".rodata.myro") USED = "custom rodata";

/* Custom writable data section (initialized) */
static uint64_t custom_counters[4] SEC(".data.mydata") ALN(64) USED = {1,2,3,4};

/* Custom zero-initialized section (like BSS) */
static uint8_t custom_scratch[256] SEC(".bss.mybss") USED;

/* Function placed into a named text subsection */
static int secret_mul(int a, int b) __attribute__((section(".text.weird")));
static int secret_mul(int a, int b) { return a * b; }

/* Place a pointer that forces relocations in rodata (often .data.rel.ro in PIC) */
static void * const ptr_to_func
  __attribute__((section(".data.rel.ro.withptr"), used)) = (void *)&secret_mul;

/* ----------------------------------------
 * Constructors / Destructors (.init_array / .fini_array)
 * ---------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
static void on_load_ctor(void) {
    /* Lands in .init_array (array of function pointers) */
    fprintf(stderr, "[ctor] library/exe loaded\n");
}

__attribute__((destructor))
static void on_unload_dtor(void) {
    /* Lands in .fini_array */
    fprintf(stderr, "[dtor] library/exe unloading\n");
}
#endif

/* ----------------------------------------
 * Weak symbols, aliases, visibility tweaks
 * ---------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int maybe_present = 123; /* weak definition */

int base_symbol = 555;

#if defined(__GNUC__) || defined(__clang__)
/* alias symbol points at base_symbol (st_value should match), same section as base_symbol */
extern int base_symbol_alias __attribute__((alias("base_symbol")));
/* hidden visibility to test st_other / binding/visibility parsing */
int hidden_thing __attribute__((visibility("hidden"))) = 9;
#endif

/* ----------------------------------------
 * Inline assembly making note/comment and truly odd sections
 * ---------------------------------------- */
#if defined(__GNUC__) || defined(__clang__)
/* A small synthetic NOTE section (format is simple but enough to parse a SHT_NOTE). */
__asm__(".pushsection .note.weird,\"a\",%note\n"
        ".align 4\n"
        /* namesz, descsz, type */
        ".long 6,4,0xBEEF\n"
        /* name (null-terminated, 6 bytes incl NUL) */
        ".ascii \"weird\\0\"\n"
        /* desc (4 bytes) */
        ".long 0xABCD1234\n"
        ".popsection\n");

/* A writable, alloc, noexec custom section with manual flags via .section */
__asm__(".pushsection .extra.data,\"aw\",@progbits\n"
        ".align 16\n"
        "extra_label:\n"
        ".quad 0x1122334455667788\n"
        ".popsection\n");

/* A non-alloc (debug-like) PROGBITS section */
__asm__(".pushsection .weird.debug,\"\",@progbits\n"
        ".ascii \"This is non-alloc debuggy text.\"\n"
        ".popsection\n");

/* A SHT_PROGBITS executable custom text section via inline asm */
__asm__(".pushsection .text.moreweird,\"ax\",@progbits\n"
        ".globl moreweird_trampoline\n"
        "moreweird_trampoline:\n"
        "  ret\n"
        ".popsection\n");
#endif

/* ----------------------------------------
 * Deliberate alignment/packing games
 * ---------------------------------------- */
struct ALN(32) BigAligned {
    uint8_t bytes[96];
};

static struct BigAligned huge_aligned SEC(".data.aligned") USED = { {0} };

/* Packed struct in a custom section (tests odd sizes) */
struct __attribute__((packed)) TinyPacked {
    uint16_t a;
    uint8_t  b;
};

static struct TinyPacked tiny SEC(".data.packed") = {0xCAFE, 0x7F};

/* ----------------------------------------
 * Function that references most of the above so it all links in
 * ---------------------------------------- */
int exercise_everything(int seed) {
    int x = add(seed, 5);
    x += hot_path(x);
    if (seed & 1) cold_path("odd seed triggers cold path");

    /* touch TLS */
#if defined(__GNUC__) || defined(__clang__)
    tls_initialized += seed;
    tls_uninitialized = x;
#endif

    /* use things so they aren’t optimized away */
    x += (int)hello_msg[0];
    x += custom_counters[seed & 3];
    custom_scratch[(unsigned)(seed) % sizeof(custom_scratch)] = (uint8_t)x;
    x += base_symbol;
#if defined(__GNUC__) || defined(__clang__)
    x += base_symbol_alias;
#endif
    x += ((int (*)(int,int))ptr_to_func)(seed, 7);
    x += maybe_present;

    /* touch the extra label emitted via inline asm to force relocation */
#if defined(__GNUC__) || defined(__clang__)
    extern unsigned long long extra_label;
    x += (int)((uintptr_t)&extra_label & 0xFFFF);
#endif
    return x;
}

/* Main keeps things simple but ensures the binary runs */
int main(void) {
    int r = exercise_everything(123);
    printf("Result=%d ; tls_initialized=%d\n", r,
#if defined(__GNUC__) || defined(__clang__)
           tls_initialized
#else
           0
#endif
    );
    return 0;
}

/* ----------------------------------------
 * Optional: symbols that end up as COMMON on some toolchains (no initializer)
 * (Many modern compilers put these into .bss directly unless -fno-common is used)
 * ---------------------------------------- */
int common_like_array[5];  /* often .bss, historically COMMON */
