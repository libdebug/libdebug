#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from cffi import FFI

ffibuilder = FFI()

ffibuilder.cdef(
    """
    typedef struct SymbolInfo
    {
        char *name;
        unsigned long long high_pc;
        unsigned long long low_pc;
        struct SymbolInfo *next;
    } SymbolInfo;

    SymbolInfo* collect_external_symbols(const char *debug_file_path, int debug_info_level);
    SymbolInfo* read_elf_info(const char *elf_file_path, int debug_info_level);
    char *get_build_id();
    char *get_debug_file();
    void free_symbol_info(SymbolInfo *head);
"""
)

with open("libdebug/cffi/debug_sym_cffi_source_legacy.c", "r") as f:
    ffibuilder.set_source(
        "libdebug.cffi.debug_sym_cffi",
        f.read(),
        libraries=["elf", "dwarf", "iberty"],
        include_dirs=[
            "/usr/include/libdwarf/libdwarf-0",
            "/usr/include/libdwarf-0",
            "/usr/include/libiberty",
        ],
    )

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
