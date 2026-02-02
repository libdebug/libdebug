//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser_shared.h"

const ElfInfo read_elf_info(const std::string &name, const int)
{
    // This function is intentionally left empty as a placeholder.
    // It should be implemented when libdwarf/libelf are available.
    ElfInfo info;
    info.build_id = "";
    info.debuglink = "";
    info.is_pie = false;
    info.entry_point = 0;
    return info;
}

SymbolVector collect_external_symbols(const std::string &debug_file_path,
                                        const std::string &reference_path,
                                        const std::string &build_id,
                                        const int debug_info_level)
{
    // This function is intentionally left empty as a placeholder.
    // It should be implemented when libdwarf/libelf are available.
    return {};
}

