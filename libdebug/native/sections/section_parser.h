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

struct SectionInfo {
    uint16_t index = 0;

    // Use raw ELF values for portability; you can wrap with enums on the Python side.
    uint32_t type = 0;      // sh_type
    char flags[16] = "";    // sh_flags parsed to fixed-size string
    uint64_t addr = 0;      // sh_addr
    uint64_t offset = 0;    // sh_offset
    uint64_t size = 0;      // sh_size
    uint64_t addralign = 0; // sh_addralign

    std::string name;       // from .shstrtab
};

struct SectionTable {
    std::vector<SectionInfo> sections;

    static SectionTable parse_file(const char* filename);
};