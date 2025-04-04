//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
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


struct SymbolInfo
{
    std::string name;
    unsigned long long high_pc;
    unsigned long low_pc;
};

using SymbolVector = std::vector<SymbolInfo>;

struct ElfInfo
{
    std::string build_id;
    std::string debuglink;
    SymbolVector symbols;
};


void add_symbol_info(SymbolVector &, const char *, const Dwarf_Addr, const Dwarf_Addr);
void process_symbol_tables(Elf *, SymbolVector &);
std::pair<const std::string, const std::string> read_build_id_and_filename(Elf *);
void process_die(Dwarf_Debug, Dwarf_Die, SymbolVector &);
void dwarf_retrieve_symbol_names(Dwarf_Debug, SymbolVector &);
void process_dwarf_info(const int, SymbolVector &);
const ElfInfo read_elf_info(const std::string &, const int);
SymbolVector collect_external_symbols(const std::string &, const int);

