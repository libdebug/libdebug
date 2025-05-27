//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/bind_vector.h>

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

const ElfInfo read_elf_info(const std::string &, const int);
SymbolVector collect_external_symbols(const std::string &, const int);
