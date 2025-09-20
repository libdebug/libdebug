//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <elf.h>

#include "../utils/binary_utils.h"

struct ProgramHeaderInfo {
    char* type = 0;      // p_type
    Elf64_Off offset = 0;    // p_offset
    Elf64_Addr vaddr = 0;     // p_vaddr
    Elf64_Addr paddr = 0;     // p_paddr
    Elf64_Xword filesz = 0;    // p_filesz
    Elf64_Xword memsz = 0;     // p_memsz
    std::string flags;     // p_flags parsed to fixed-size string
    Elf64_Xword align = 0;     // p_align
};

struct ProgramHeaderTable {
    std::vector<ProgramHeaderInfo> headers;

    static ProgramHeaderTable parse_file(const char* filename);
};