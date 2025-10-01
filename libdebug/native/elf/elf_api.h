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

// -------------------- Section Structures -------------------- //

struct SectionInfo {
    uint16_t index = 0;

    // Use raw ELF values for portability; you can wrap with enums on the Python side.
    std::string type;      // sh_type
    std::string flags;    // sh_flags parsed to fixed-size string
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

template <typename PhdrT>
struct LoadSeg { uint64_t vaddr, memsz, off, filesz; };

// -------------------- Dynamic Section Structures -------------------- //

enum class DynSectionValueType {
    DYN_VAL_NONE,
    DYN_VAL_NUM,
    DYN_VAL_STR,
    DYN_VAL_ADDR,
    DYN_VAL_FLAGS,
    DYN_VAL_FLAGS1,
    DYN_VAL_FEATURES,
    DYN_VAL_POSFLAG1
};

struct RawDynEnt {
    int64_t tag;
    uint64_t val; // raw d_un after endianness fix, widened
};

struct DynamicSectionInfo {
    std::string tag; // e.g. NEEDED
    uint64_t val;    // e.g. 0x7f
    std::string val_str; // e.g. "libc.so.6"
    DynSectionValueType val_type; // type of val (e.g., number of bytes, string, address)
};

struct DynamicSectionTable {
    std::vector<DynamicSectionInfo> entries;

    static DynamicSectionTable parse_file(const char* filename);
};


// -------------------- Program Header Structures -------------------- //

struct ProgramHeaderInfo {
    std::string type;      // p_type mnemonic
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

// -------------------- Property Descriptor -------------------- //

struct GNUPropertyDescriptor {
    std::string type;
    std::vector<uint8_t> data;
    bool is_bit_mask;
    std::string bit_mnemonics; // e.g. "BTI PAC"
};

struct GNUPropertyNotesTable {
    std::vector<GNUPropertyDescriptor> properties;

    // Parse GNU property notes from an ELF file. The section/segment inputs are
    // file offsets and sizes. Use 0 for offset/size when not available.
    static GNUPropertyNotesTable parse_file(const char* filename,
                                            const size_t section_off, const size_t section_size,
                                            const size_t segment_off, const size_t segment_size);
};