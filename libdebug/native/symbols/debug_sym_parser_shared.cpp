//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser_shared.h"

namespace nb = nanobind;

NB_MODULE(libdebug_debug_sym_parser, m)
{
    nb::bind_vector<SymbolVector>(m, "SymbolVector", "A vector of symbols");

    nb::class_<SymbolInfo>(m, "SymbolInfo", "Symbol information")
        .def_ro("name", &SymbolInfo::name, "The name of the symbol")
        .def_ro("low_pc", &SymbolInfo::low_pc, "The low address of the symbol")
        .def_ro("high_pc", &SymbolInfo::high_pc, "The high address of the symbol");

    nb::class_<ElfInfo>(m, "ElfInfo", "Information about an ELF file")
        .def_ro("build_id", &ElfInfo::build_id, "The build ID of the ELF file")
        .def_ro("debuglink", &ElfInfo::debuglink, "The debug link of the ELF file")
        .def_ro("symbols", &ElfInfo::symbols, "The symbols of the ELF file");

    m.def(
        "read_elf_info",
        &read_elf_info,
        nb::arg("elf_file_path"),
        nb::arg("debug_info_level"),
        "Read the symbol table and the build ID from an ELF file\n"
        "\n"
        "Args:\n"
        "    elf_file_path (str): The path to the ELF file\n"
        "    debug_info_level (int): The debug info level for parsing.\n"
        "\n"
        "Returns:\n"
        "    tuple: A tuple containing the symbol table, the build ID and the debug file path"
    );

    m.def(
        "collect_external_symbols",
        &collect_external_symbols,
        nb::arg("debug_file_path"),
        nb::arg("debug_info_level"),
        "Collect the external symbols from a debug file\n"
        "\n"
        "Args:\n"
        "    debug_file_path (str): The path to the debug file\n"
        "    debug_info_level (int): The debug info level for parsing.\n"
        "\n"
        "Returns:\n"
        "    list: A list of external symbols"
    );

#ifdef HAS_SYMBOL_SUPPORT
    m.attr("HAS_SYMBOL_SUPPORT") = true;
#else
    m.attr("HAS_SYMBOL_SUPPORT") = false;
#endif
}
