//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025-2026 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <string>
#include <vector>
#include <cstdint>

#ifdef HAS_SYMBOL_SUPPORT
    #include <elf.h>
#else
    #define STT_NOTYPE 0
    #define STT_OBJECT 1
    #define STT_FUNC 2
    #define STT_SECTION 3
    #define STT_FILE 4
    #define STT_COMMON 5
    #define STT_TLS 6
    #define STT_GNU_IFUNC 10

    #define STB_LOCAL 0
    #define STB_GLOBAL 1
    #define STB_WEAK 2
    #define STB_GNU_UNIQUE 10

    #define STV_DEFAULT 0
    #define STV_INTERNAL 1
    #define STV_HIDDEN 2
    #define STV_PROTECTED 3
#endif

// Symbol types (matching ELF STT_* values)
enum class SymbolType : uint8_t {
    NOTYPE = STT_NOTYPE,
    OBJECT = STT_OBJECT,
    FUNC = STT_FUNC,
    SECTION = STT_SECTION,
    FILE = STT_FILE,
    COMMON = STT_COMMON,
    TLS = STT_TLS,
    GNU_IFUNC = STT_GNU_IFUNC,
    UNKNOWN = 255
};

// Symbol binding (matching ELF STB_* values)
enum class SymbolBinding : uint8_t {
    LOCAL = STB_LOCAL,
    GLOBAL = STB_GLOBAL,
    WEAK = STB_WEAK,
    GNU_UNIQUE = STB_GNU_UNIQUE,
    UNKNOWN = 255
};

// Symbol visibility (matching ELF STV_* values)
enum class SymbolVisibility : uint8_t {
    DEFAULT = STV_DEFAULT,
    INTERNAL = STV_INTERNAL,
    HIDDEN = STV_HIDDEN,
    PROTECTED = STV_PROTECTED,
    UNKNOWN = 255
};

struct SymbolInfo
{
    std::string name;
    std::string demangled_name;      // Demangled name for C++ symbols
    unsigned long long high_pc;      // End address (called "end" in Python)
    unsigned long long low_pc;       // Start address (called "start" in Python)
    SymbolType type;                 // Symbol type (FUNC, OBJECT, TLS, etc.)
    SymbolBinding binding;           // Symbol binding (LOCAL, GLOBAL, WEAK)
    SymbolVisibility visibility;     // Symbol visibility
    uint16_t section_index;          // Section index
    bool is_tls;                     // True if this is a TLS symbol
    int64_t tls_offset;              // Offset within TLS block (for TLS symbols)
    int32_t tls_module_id;           // TLS module ID (-1 if unknown)
    std::string version;             // Symbol version (e.g., "GLIBC_2.2.5")
    bool is_plt;                     // True if PLT entry
    bool is_got;                     // True if GOT entry

    // Runtime context fields (set when symbols are loaded into a process)
    std::string backing_file;        // The file the symbol comes from at runtime
    std::string reference_file;      // The file the symbol's offsets refer to
    std::string reference_build_id;  // Build ID of the reference file
    bool is_external;                // True if from external debug info

    SymbolInfo()
        : name()
        , demangled_name()
        , high_pc(0)
        , low_pc(0)
        , type(SymbolType::NOTYPE)
        , binding(SymbolBinding::GLOBAL)
        , visibility(SymbolVisibility::DEFAULT)
        , section_index(0)
        , is_tls(false)
        , tls_offset(0)
        , tls_module_id(-1)
        , version()
        , is_plt(false)
        , is_got(false)
        , backing_file()
        , reference_file()
        , reference_build_id()
        , is_external(false)
    {}

    // Computed properties
    unsigned long long size() const { return high_pc - low_pc; }
    bool is_function() const { return type == SymbolType::FUNC || type == SymbolType::GNU_IFUNC; }
    bool is_object() const { return type == SymbolType::OBJECT; }
    bool is_weak() const { return binding == SymbolBinding::WEAK; }
    bool is_local() const { return binding == SymbolBinding::LOCAL; }
    bool is_global() const { return binding == SymbolBinding::GLOBAL; }
    bool is_defined() const { return section_index != 0; }
    const std::string& display_name() const { return demangled_name.empty() ? name : demangled_name; }

    // Equality comparison
    bool operator==(const SymbolInfo& other) const {
        return name == other.name &&
               low_pc == other.low_pc &&
               high_pc == other.high_pc &&
               type == other.type &&
               binding == other.binding &&
               backing_file == other.backing_file &&
               reference_file == other.reference_file &&
               is_external == other.is_external;
    }

    // Return a Python-style repr for this SymbolInfo
    std::string repr() const;
};

using SymbolVector = std::vector<SymbolInfo>;

// TLS information for a loaded module
struct TLSModuleInfo
{
    std::string module_path;
    int32_t module_id;               // Module ID for TLS resolution
    uint64_t tls_block_size;         // Size of the TLS block
    uint64_t tls_block_align;        // Alignment of the TLS block
    uint64_t tls_init_image_addr;    // Address of the TLS initialization image
    uint64_t tls_init_image_size;    // Size of the TLS initialization image
    uint64_t base_offset;    // Offset of this module's TLS data in the block

    TLSModuleInfo()
        : module_path()
        , module_id(-1)
        , tls_block_size(0)
        , tls_block_align(0)
        , tls_init_image_addr(0)
        , tls_init_image_size(0)
        , base_offset(0)
    {}
};

using TlsModuleVector = std::vector<TLSModuleInfo>;

struct ElfInfo
{
    std::string build_id;
    std::string debuglink;
    SymbolVector symbols;
    TLSModuleInfo tls_info;          // TLS information for this ELF
    bool is_pie;                      // True if position-independent executable
    uint64_t entry_point;             // Entry point address
};
