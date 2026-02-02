//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_structs.h"
#include <string>
#include <sstream>
#include <iomanip>

static const char* symbol_type_name(SymbolType t) {
    switch (t) {
        case SymbolType::NOTYPE: return "NOTYPE";
        case SymbolType::OBJECT: return "OBJECT";
        case SymbolType::FUNC: return "FUNC";
        case SymbolType::SECTION: return "SECTION";
        case SymbolType::FILE: return "FILE";
        case SymbolType::COMMON: return "COMMON";
        case SymbolType::TLS: return "TLS";
        case SymbolType::GNU_IFUNC: return "IFUNC";
        default: return "UNKNOWN";
    }
}

static const char* symbol_binding_name(SymbolBinding b) {
    switch (b) {
        case SymbolBinding::LOCAL: return "LOCAL";
        case SymbolBinding::GLOBAL: return "GLOBAL";
        case SymbolBinding::WEAK: return "WEAK";
        case SymbolBinding::GNU_UNIQUE: return "UNIQUE";
        default: return "UNKNOWN";
    }
}

std::string SymbolInfo::repr() const
{
    std::ostringstream oss;
    oss << "Symbol(start=0x" << std::hex << low_pc
        << ", end=0x" << high_pc << std::dec
        << ", name='" << name << "'"
        << ", type=" << symbol_type_name(type)
        << ", binding=" << symbol_binding_name(binding);

    if (is_tls) {
        oss << ", tls_offset=" << tls_offset;
        if (tls_module_id >= 0) {
            oss << ", tls_module_id=" << tls_module_id;
        }
    }

    if (!demangled_name.empty() && demangled_name != name) {
        oss << ", demangled='" << demangled_name << "'";
    }

    if (!version.empty()) {
        oss << ", version='" << version << "'";
    }

    if (is_plt) oss << ", plt=True";
    if (is_got) oss << ", got=True";

    if (!backing_file.empty()) {
        oss << ", backing_file='" << backing_file << "'";
    }
    oss << ", is_external=" << (is_external ? "True" : "False");

    oss << ")";
    return oss.str();
}
