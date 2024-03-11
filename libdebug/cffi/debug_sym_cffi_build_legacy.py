#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
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
