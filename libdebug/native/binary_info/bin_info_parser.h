//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/bind_vector.h>

#include <dwarf.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>

// Data structures
struct SymbolInfo
{
    std::string name;
    unsigned long long high_pc;
    unsigned long low_pc;
};

struct SectionInfo
{
    std::string name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
};

using SymbolVector = std::vector<SymbolInfo>;
using SectionLayout = std::vector<SectionInfo>;

// Exported functions
SymbolVector parse_binary_symbols(const std::string &elf_file_path, const int debug_info_level);
SymbolVector collect_external_symbols(const std::string &, const int);
SectionLayout parse_section_layout(const std::string &elf_file_path);
std::pair<const std::string, const std::string> read_build_id_and_filename(const std::string &elf_file_path);

// Internal functions
void add_symbol_info(SymbolVector &, const char *, const Dwarf_Addr, const Dwarf_Addr);
void process_symbol_tables(Elf *, SymbolVector &);
void process_section_layout(Elf *, SectionLayout &);
std::pair<const std::string, const std::string> read_build_id_and_filename(Elf *);
void process_die(Dwarf_Debug, Dwarf_Die, SymbolVector &);
void dwarf_retrieve_symbol_names(Dwarf_Debug, SymbolVector &);
void process_dwarf_info(const int, SymbolVector &);