//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025-2026 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser_shared.h"

namespace nb = nanobind;

NB_MODULE(libdebug_debug_sym_parser, m)
{
    // Bind enums
    nb::enum_<SymbolType>(m, "SymbolType", "ELF symbol types", nb::is_arithmetic())
        .value("NOTYPE", SymbolType::NOTYPE, "No type specified")
        .value("OBJECT", SymbolType::OBJECT, "Data object (variable, array)")
        .value("FUNC", SymbolType::FUNC, "Function or code")
        .value("SECTION", SymbolType::SECTION, "Section symbol")
        .value("FILE", SymbolType::FILE, "Source file symbol")
        .value("COMMON", SymbolType::COMMON, "Common block symbol")
        .value("TLS", SymbolType::TLS, "Thread-local storage")
        .value("GNU_IFUNC", SymbolType::GNU_IFUNC, "GNU indirect function")
        .value("UNKNOWN", SymbolType::UNKNOWN, "Unknown symbol type")
        .export_values();

    nb::enum_<SymbolBinding>(m, "SymbolBinding", "ELF symbol binding", nb::is_arithmetic())
        .value("LOCAL", SymbolBinding::LOCAL, "Not visible outside object file")
        .value("GLOBAL", SymbolBinding::GLOBAL, "Visible to all object files")
        .value("WEAK", SymbolBinding::WEAK, "Like global, but lower precedence")
        .value("GNU_UNIQUE", SymbolBinding::GNU_UNIQUE, "Unique symbol")
        .value("UNKNOWN", SymbolBinding::UNKNOWN, "Unknown binding")
        .export_values();

    nb::enum_<SymbolVisibility>(m, "SymbolVisibility", "ELF symbol visibility", nb::is_arithmetic())
        .value("DEFAULT", SymbolVisibility::DEFAULT, "Default visibility")
        .value("INTERNAL", SymbolVisibility::INTERNAL, "Processor-specific hidden")
        .value("HIDDEN", SymbolVisibility::HIDDEN, "Not visible from other components")
        .value("PROTECTED", SymbolVisibility::PROTECTED, "Protected (cannot be preempted)")
        .value("UNKNOWN", SymbolVisibility::UNKNOWN, "Unknown visibility")
        .export_values();

    // Bind vectors
    nb::bind_vector<SymbolVector>(m, "SymbolVector", "A vector of symbols");
    nb::bind_vector<TlsModuleVector>(m, "TlsModuleVector", "A vector of TLS module info");

    // Bind SymbolInfo struct as "Symbol" for Python use
    nb::class_<SymbolInfo>(m, "Symbol", "A symbol in the target process")
        // Full constructor for creating symbols
        .def("__init__", [](SymbolInfo *self,
                           const std::string &name,
                           const std::string &demangled_name,
                           unsigned long long low_pc,
                           unsigned long long high_pc,
                           SymbolType type,
                           SymbolBinding binding,
                           SymbolVisibility visibility,
                           uint16_t section_index,
                           bool is_tls,
                           int64_t tls_offset,
                           int32_t tls_module_id,
                           const std::string &version,
                           bool is_plt,
                           bool is_got,
                           const std::string &backing_file,
                           const std::string &reference_file,
                           const std::string &reference_build_id,
                           bool is_external) {
            new (self) SymbolInfo();
            self->name = name;
            self->demangled_name = demangled_name;
            self->low_pc = low_pc;
            self->high_pc = high_pc;
            self->type = type;
            self->binding = binding;
            self->visibility = visibility;
            self->section_index = section_index;
            self->is_tls = is_tls;
            self->tls_offset = tls_offset;
            self->tls_module_id = tls_module_id;
            self->version = version;
            self->is_plt = is_plt;
            self->is_got = is_got;
            self->backing_file = backing_file;
            self->reference_file = reference_file;
            self->reference_build_id = reference_build_id;
            self->is_external = is_external;
        }, nb::arg("name") = "",
           nb::arg("demangled_name") = "",
           nb::arg("low_pc") = 0,
           nb::arg("high_pc") = 0,
           nb::arg("type") = SymbolType::NOTYPE,
           nb::arg("binding") = SymbolBinding::GLOBAL,
           nb::arg("visibility") = SymbolVisibility::DEFAULT,
           nb::arg("section_index") = 0,
           nb::arg("is_tls") = false,
           nb::arg("tls_offset") = 0,
           nb::arg("tls_module_id") = -1,
           nb::arg("version") = "",
           nb::arg("is_plt") = false,
           nb::arg("is_got") = false,
           nb::arg("backing_file") = "",
           nb::arg("reference_file") = "",
           nb::arg("reference_build_id") = "",
           nb::arg("is_external") = false,
           "Constructor with all parameters")
        .def_ro("name", &SymbolInfo::name, "The name of the symbol")
        .def_ro("demangled_name", &SymbolInfo::demangled_name, "The demangled name (for C++ symbols)")
        .def_prop_ro("start", [](const SymbolInfo& s) { return s.low_pc; }, "The start address of the symbol")
        .def_prop_ro("end", [](const SymbolInfo& s) { return s.high_pc; }, "The end address of the symbol")
        .def_ro("low_pc", &SymbolInfo::low_pc, "The low address of the symbol (alias for start)")
        .def_ro("high_pc", &SymbolInfo::high_pc, "The high address of the symbol (alias for end)")
        .def_prop_ro("symbol_type", [](const SymbolInfo& s) { return s.type; }, "The symbol type (FUNC, OBJECT, TLS, etc.)")
        .def_ro("type", &SymbolInfo::type, "The symbol type (alias for symbol_type)")
        .def_ro("binding", &SymbolInfo::binding, "The symbol binding (LOCAL, GLOBAL, WEAK)")
        .def_ro("visibility", &SymbolInfo::visibility, "The symbol visibility")
        .def_ro("section_index", &SymbolInfo::section_index, "The ELF section index")
        .def_ro("is_tls", &SymbolInfo::is_tls, "Whether this is a TLS symbol")
        .def_ro("tls_offset", &SymbolInfo::tls_offset, "Offset within TLS block")
        .def_ro("tls_module_id", &SymbolInfo::tls_module_id, "TLS module ID")
        .def_ro("is_plt", &SymbolInfo::is_plt, "Whether this is a PLT entry")
        .def_ro("is_got", &SymbolInfo::is_got, "Whether this is a GOT entry")
        .def_ro("version", &SymbolInfo::version, "Symbol version string")
        .def_ro("backing_file", &SymbolInfo::backing_file, "The file the symbol comes from at runtime")
        .def_ro("reference_file", &SymbolInfo::reference_file, "The file the symbol's offsets refer to")
        .def_ro("reference_build_id", &SymbolInfo::reference_build_id, "Build ID of the reference file")
        .def_ro("is_external", &SymbolInfo::is_external, "Whether from external debug info")
        .def_prop_ro("size", &SymbolInfo::size, "The size of the symbol (end - start)")
        .def_prop_ro("is_function", &SymbolInfo::is_function, "True if this is a function symbol")
        .def_prop_ro("is_object", &SymbolInfo::is_object, "True if this is a data object symbol")
        .def_prop_ro("is_weak", &SymbolInfo::is_weak, "True if this is a weak symbol")
        .def_prop_ro("is_local", &SymbolInfo::is_local, "True if this is a local symbol")
        .def_prop_ro("is_global", &SymbolInfo::is_global, "True if this is a global symbol")
        .def_prop_ro("is_defined", &SymbolInfo::is_defined, "True if this symbol is defined (not undefined)")
        .def_prop_ro("display_name", &SymbolInfo::display_name, "The best display name (demangled if available)")
        .def("__repr__", &SymbolInfo::repr)
        .def("__eq__", &SymbolInfo::operator==);

    // Bind TLSModuleInfo struct
    nb::class_<TLSModuleInfo>(m, "TLSModuleInfo", "TLS module information")
        .def(nb::init<>(), "Default constructor")
        .def_ro("module_path", &TLSModuleInfo::module_path, "Path to the module")
        .def_rw("module_id", &TLSModuleInfo::module_id, "Module ID for TLS resolution")
        .def_ro("tls_block_size", &TLSModuleInfo::tls_block_size, "Size of the TLS block")
        .def_ro("tls_block_align", &TLSModuleInfo::tls_block_align, "Alignment of the TLS block")
        .def_ro("tls_init_image_addr", &TLSModuleInfo::tls_init_image_addr, "Address of TLS init image")
        .def_ro("tls_init_image_size", &TLSModuleInfo::tls_init_image_size, "Size of TLS init image")
        .def_ro("base_offset", &TLSModuleInfo::base_offset, "base_offset");

    // Bind ElfInfo struct
    nb::class_<ElfInfo>(m, "ElfInfo", "Information about an ELF file")
        .def_ro("build_id", &ElfInfo::build_id, "The build ID of the ELF file")
        .def_ro("debuglink", &ElfInfo::debuglink, "The debug link of the ELF file")
        .def_ro("symbols", &ElfInfo::symbols, "The symbols of the ELF file")
        .def_ro("tls_info", &ElfInfo::tls_info, "TLS information for this ELF")
        .def_ro("is_pie", &ElfInfo::is_pie, "Whether this is a PIE binary")
        .def_ro("entry_point", &ElfInfo::entry_point, "The entry point address");

    // Main functions
    m.def(
        "read_elf_info",
        &read_elf_info,
        nb::arg("elf_file_path"),
        nb::arg("debug_info_level"),
        "Read symbol table, build ID, TLS info and other metadata from an ELF file\n"
        "\n"
        "Args:\n"
        "    elf_file_path (str): The path to the ELF file\n"
        "    debug_info_level (int): The debug info level for parsing.\n"
        "        Level 0: Disabled\n"
        "        Level 1: Parse symbol tables (.symtab, .dynsym)\n"
        "        Level 2: Also parse DWARF\n"
        "        Level 3: Follow external debug files\n"
        "        Level 4: Parse external DWARF\n"
        "        Level 5: Use debuginfod\n"
        "\n"
        "Returns:\n"
        "    ElfInfo: Information about the ELF file including symbols"
    );

    m.def(
        "collect_external_symbols",
        &collect_external_symbols,
        nb::arg("debug_file_path"),
        nb::arg("reference_path"),
        nb::arg("build_id"),
        nb::arg("debug_info_level"),
        "Collect symbols from an external debug file\n"
        "\n"
        "Args:\n"
        "    debug_file_path (str): The path to the debug file\n"
        "    reference_path (str): The path to the reference file for symbol offsets\n"
        "    build_id (str): The build ID of the reference file\n"
        "    debug_info_level (int): The debug info level for parsing.\n"
        "\n"
        "Returns:\n"
        "    SymbolVector: A list of symbols from the debug file"
    );

#ifdef HAS_SYMBOL_SUPPORT
    m.attr("HAS_SYMBOL_SUPPORT") = true;
#else
    m.attr("HAS_SYMBOL_SUPPORT") = false;
#endif
}

