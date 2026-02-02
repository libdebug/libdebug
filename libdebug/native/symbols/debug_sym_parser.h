//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2026 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include "debug_sym_structs.h"

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <dwarf.h>
#include <unistd.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>

// Symbol table processing
void process_symbol_tables(Elf *, SymbolVector &);

// Symbol demangling
std::string demangle_symbol(const char *);

// Build ID and debug link reading
std::pair<const std::string, const std::string> read_build_id_and_filename(Elf *);

// TLS information reading
TLSModuleInfo read_tls_info(Elf *, const std::string &);

// PIE detection
bool is_elf_pie(Elf *);

// Entry point reading
uint64_t get_elf_entry_point(Elf *);

// DWARF processing
void process_die(Dwarf_Debug, Dwarf_Die, SymbolVector &);
void dwarf_retrieve_symbol_names(Dwarf_Debug, SymbolVector &);
void process_dwarf_info(const int, SymbolVector &);

