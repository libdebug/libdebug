//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2026 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser.h"

#ifdef HAS_LIBIBERTY
    #define HAVE_DECL_BASENAME 1
    #include <demangle.h>
#endif

#include <fcntl.h>
#include <gelf.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <cstring>
#include <unordered_map>
#include <algorithm>

// Helper function to convert ELF symbol type to our enum
static SymbolType elf_type_to_symbol_type(unsigned char st_type)
{
    switch (st_type) {
        case STT_NOTYPE: return SymbolType::NOTYPE;
        case STT_OBJECT: return SymbolType::OBJECT;
        case STT_FUNC: return SymbolType::FUNC;
        case STT_SECTION: return SymbolType::SECTION;
        case STT_FILE: return SymbolType::FILE;
        case STT_COMMON: return SymbolType::COMMON;
        case STT_TLS: return SymbolType::TLS;
        case STT_GNU_IFUNC: return SymbolType::GNU_IFUNC;
        default: return SymbolType::UNKNOWN;
    }
}

// Helper function to convert ELF symbol binding to our enum
static SymbolBinding elf_binding_to_symbol_binding(unsigned char st_bind)
{
    switch (st_bind) {
        case STB_LOCAL: return SymbolBinding::LOCAL;
        case STB_GLOBAL: return SymbolBinding::GLOBAL;
        case STB_WEAK: return SymbolBinding::WEAK;
        case STB_GNU_UNIQUE: return SymbolBinding::GNU_UNIQUE;
        default: return SymbolBinding::UNKNOWN;
    }
}

// Helper function to convert ELF visibility to our enum
static SymbolVisibility elf_visibility_to_symbol_visibility(unsigned char st_other)
{
    unsigned char vis = ELF64_ST_VISIBILITY(st_other);
    switch (vis) {
        case STV_DEFAULT: return SymbolVisibility::DEFAULT;
        case STV_INTERNAL: return SymbolVisibility::INTERNAL;
        case STV_HIDDEN: return SymbolVisibility::HIDDEN;
        case STV_PROTECTED: return SymbolVisibility::PROTECTED;
        default: return SymbolVisibility::UNKNOWN;
    }
}

// Demangle a symbol name if possible
std::string demangle_symbol(const char *name)
{
#ifdef HAS_LIBIBERTY
    if (!name || name[0] == '\0') {
        return "";
    }

    char *demangled = cplus_demangle_v3(name, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
    if (demangled) {
        std::string result(demangled);
        free(demangled);
        return result;
    }
#endif
    return "";
}

// Add a symbol to the vector with all metadata
static void add_symbol_info(SymbolVector &symbols, const char *name, uint64_t low_pc, uint64_t high_pc,
                            SymbolType type, SymbolBinding binding, SymbolVisibility visibility,
                            uint16_t section_index, bool is_tls, int64_t tls_offset,
                            const std::string &version, bool is_plt, bool is_got)
{
    if (!name || name[0] == '\0') {
        return;  // Skip empty names
    }

    symbols.emplace_back();

    SymbolInfo &symbol_info = symbols.back();
    symbol_info.name = name;
    symbol_info.demangled_name = demangle_symbol(name);
    symbol_info.low_pc = low_pc;
    symbol_info.high_pc = high_pc;
    symbol_info.type = type;
    symbol_info.binding = binding;
    symbol_info.visibility = visibility;
    symbol_info.section_index = section_index;
    symbol_info.is_tls = is_tls;
    symbol_info.tls_offset = tls_offset;
    symbol_info.tls_module_id = -1;  // Will be set at runtime
    symbol_info.version = version;
    symbol_info.is_plt = is_plt;
    symbol_info.is_got = is_got;
}

// Read symbol version information from .gnu.version and .gnu.version_d/.gnu.version_r sections
static std::unordered_map<uint32_t, std::string> read_symbol_versions(Elf *elf, Elf_Scn *verdef_scn, Elf_Scn *verneed_scn)
{
    std::unordered_map<uint32_t, std::string> version_map;

    // Process version definitions (for symbols defined in this object)
    if (verdef_scn) {
        GElf_Shdr verdef_shdr;
        if (gelf_getshdr(verdef_scn, &verdef_shdr) == &verdef_shdr) {
            Elf_Data *verdef_data = elf_getdata(verdef_scn, NULL);
            if (verdef_data) {
                size_t offset = 0;
                while (offset < verdef_data->d_size) {
                    GElf_Verdef verdef;
                    if (gelf_getverdef(verdef_data, offset, &verdef) == NULL) {
                        break;
                    }

                    // Get the first aux entry (contains the version name)
                    GElf_Verdaux verdaux;
                    if (gelf_getverdaux(verdef_data, offset + verdef.vd_aux, &verdaux) != NULL) {
                        char *ver_name = elf_strptr(elf, verdef_shdr.sh_link, verdaux.vda_name);
                        if (ver_name) {
                            version_map[verdef.vd_ndx] = ver_name;
                        }
                    }

                    if (verdef.vd_next == 0) break;
                    offset += verdef.vd_next;
                }
            }
        }
    }

    // Process version requirements (for symbols needed from other objects)
    if (verneed_scn) {
        GElf_Shdr verneed_shdr; // Corrected variable name
        if (gelf_getshdr(verneed_scn, &verneed_shdr) == &verneed_shdr) {
            Elf_Data *verneed_data = elf_getdata(verneed_scn, NULL);
            if (verneed_data) {
                size_t offset = 0;
                while (offset < verneed_data->d_size) {
                    GElf_Verneed verneed;
                    if (gelf_getverneed(verneed_data, offset, &verneed) == NULL) {
                        break;
                    }

                    // Process aux entries
                    size_t aux_offset = offset + verneed.vn_aux;
                    for (uint16_t i = 0; i < verneed.vn_cnt; i++) {
                        GElf_Vernaux vernaux;
                        if (gelf_getvernaux(verneed_data, aux_offset, &vernaux) != NULL) {
                            char *ver_name = elf_strptr(elf, verneed_shdr.sh_link, vernaux.vna_name);
                            if (ver_name) {
                                version_map[vernaux.vna_other] = ver_name;
                            }
                        }
                        if (vernaux.vna_next == 0) break;
                        aux_offset += vernaux.vna_next;
                    }

                    if (verneed.vn_next == 0) break;
                    offset += verneed.vn_next;
                }
            }
        }
    }

    return version_map;
}

// Get version string for a symbol index
static std::string get_symbol_version(Elf *elf, Elf_Scn *versym_scn, size_t sym_index,
                                       const std::unordered_map<uint32_t, std::string> &version_map)
{
    if (!versym_scn) {
        return "";
    }

    GElf_Shdr versym_shdr;
    if (gelf_getshdr(versym_scn, &versym_shdr) != &versym_shdr) {
        return "";
    }

    Elf_Data *versym_data = elf_getdata(versym_scn, NULL);
    if (!versym_data) {
        return "";
    }

    // Version symbol table contains 16-bit version indices
    size_t offset = sym_index * sizeof(GElf_Versym);
    if (offset + sizeof(GElf_Versym) > versym_data->d_size) {
        return "";
    }

    GElf_Versym versym;
    if (gelf_getversym(versym_data, sym_index, &versym) == NULL) {
        return "";
    }

    // Mask out the hidden bit
    uint16_t ver_index = versym & 0x7fff;

    // Skip special version indices
    if (ver_index == VER_NDX_LOCAL || ver_index == VER_NDX_GLOBAL) {
        return "";  // VER_NDX_LOCAL or VER_NDX_GLOBAL
    }

    auto it = version_map.find(ver_index);
    if (it != version_map.end()) {
        return it->second;
    }

    return "";
}

struct ElfSections {
    Elf_Scn *versym_scn = NULL;
    Elf_Scn *verdef_scn = NULL;
    Elf_Scn *verneed_scn = NULL;
    std::vector<Elf_Scn*> symbol_sections;
    uint64_t plt_start = 0;
    uint64_t plt_end = 0;
    uint64_t got_start = 0;
    uint64_t got_end = 0;
    uint64_t gotplt_start = 0;
    uint64_t gotplt_end = 0;
};

static ElfSections scan_elf_sections(Elf *elf)
{
    ElfSections sections;
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;

    if (!gelf_getehdr(elf, &ehdr)) {
        throw std::runtime_error("Failed to read ELF header");
    }

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        if (shdr.sh_type == SHT_GNU_versym) {
            sections.versym_scn = scn;
        } else if (shdr.sh_type == SHT_GNU_verdef) {
            sections.verdef_scn = scn;
        } else if (shdr.sh_type == SHT_GNU_verneed) {
            sections.verneed_scn = scn;
        } else if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            sections.symbol_sections.push_back(scn);
        }

        char *name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (!name) continue;

        if (strcmp(name, ".plt") == 0 || strcmp(name, ".plt.sec") == 0 || strcmp(name, ".plt.got") == 0) {
            if (sections.plt_start == 0 || shdr.sh_addr < sections.plt_start) {
                sections.plt_start = shdr.sh_addr;
            }
            if (shdr.sh_addr + shdr.sh_size > sections.plt_end) {
                sections.plt_end = shdr.sh_addr + shdr.sh_size;
            }
        } else if (strcmp(name, ".got") == 0) {
            sections.got_start = shdr.sh_addr;
            sections.got_end = shdr.sh_addr + shdr.sh_size;
        } else if (strcmp(name, ".got.plt") == 0) {
            sections.gotplt_start = shdr.sh_addr;
            sections.gotplt_end = shdr.sh_addr + shdr.sh_size;
        }
    }

    return sections;
}

void process_symbol_tables(Elf *elf, SymbolVector &symbols)
{
    GElf_Shdr shdr;
    Elf_Data *data;
    GElf_Ehdr ehdr;

    if (!gelf_getehdr(elf, &ehdr)) {
        throw std::runtime_error("Failed to read ELF header");
    }

    // First pass: locate all relevant sections
    ElfSections sections = scan_elf_sections(elf);

    // Read version information
    auto version_map = read_symbol_versions(elf, sections.verdef_scn, sections.verneed_scn);

    // Process symbol tables
    for (Elf_Scn *sym_scn : sections.symbol_sections) {
        if (gelf_getshdr(sym_scn, &shdr) != &shdr) continue;

        data = elf_getdata(sym_scn, NULL);
        if (!data) continue;

        int count = shdr.sh_size / shdr.sh_entsize;

        for (int i = 0; i < count; ++i) {
            GElf_Sym sym;
            if (gelf_getsym(data, i, &sym) == NULL) {
                continue;
            }

            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') {
                continue;
            }

            uint64_t low_pc = sym.st_value;
            uint64_t high_pc = sym.st_value + sym.st_size;

            // Get symbol metadata
            unsigned char st_type = GELF_ST_TYPE(sym.st_info);
            unsigned char st_bind = GELF_ST_BIND(sym.st_info);

            SymbolType type = elf_type_to_symbol_type(st_type);
            SymbolBinding binding = elf_binding_to_symbol_binding(st_bind);
            SymbolVisibility visibility = elf_visibility_to_symbol_visibility(sym.st_other);

            // Check if this is a TLS symbol
            bool is_tls = (type == SymbolType::TLS);
            int64_t tls_offset = 0;
            if (is_tls) {
                // For TLS symbols, st_value is the offset within the TLS block
                tls_offset = static_cast<int64_t>(sym.st_value);
            }

            // Get version string
            std::string version = "";
            if (shdr.sh_type == SHT_DYNSYM) {
                version = get_symbol_version(elf, sections.versym_scn, i, version_map);
            }

            // Check if symbol is in PLT or GOT
            bool is_plt = (low_pc >= sections.plt_start && low_pc < sections.plt_end && sections.plt_start != 0);
            bool is_got = (low_pc >= sections.got_start && low_pc < sections.got_end && sections.got_start != 0) ||
                            (low_pc >= sections.gotplt_start && low_pc < sections.gotplt_end && sections.gotplt_start != 0);

            // Mark undefined function symbols from dynsym as PLT (they're resolved via PLT)
            if (sym.st_shndx == SHN_UNDEF && shdr.sh_type == SHT_DYNSYM && 
                st_type == STT_FUNC && sections.plt_start != 0) {
                is_plt = true;
            }

            // Skip symbols with zero address (unless TLS or undefined)
            if (low_pc == 0 && !is_tls && sym.st_shndx != SHN_UNDEF) {
                continue;
            }

            add_symbol_info(symbols, name, low_pc, high_pc, type, binding, visibility,
                            sym.st_shndx, is_tls, tls_offset, version, is_plt, is_got);
        }
    }
}

std::pair<const std::string, const std::string> read_build_id_and_filename(Elf *elf)
{
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;
    Elf_Scn *section = NULL;
    char *build_id = NULL, *debuglink = NULL;

    if (!gelf_getehdr(elf, &ehdr)) {
        throw std::runtime_error("Failed to read ELF header");
    }

    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (!gelf_getshdr(section, &shdr)) {
            continue;
        }

        char *name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (shdr.sh_type == SHT_NOTE) {
            if (name && strcmp(name, ".note.gnu.build-id") == 0) {
                Elf_Data *data = elf_getdata(section, NULL);

                if (data) {
                    GElf_Nhdr nhdr;
                    size_t offset = 0;
                    size_t name_offset, desc_offset;

                    while ((offset = gelf_getnote(data, offset, &nhdr, &name_offset, &desc_offset)) != 0) {
                        if (nhdr.n_type == NT_GNU_BUILD_ID) {
                            build_id = (char *) malloc(nhdr.n_descsz * 2 + 1);
                            unsigned char *desc = (unsigned char *)data->d_buf + desc_offset;
                            for (size_t i = 0; i < nhdr.n_descsz; i++) {
                                sprintf(build_id + (i * 2), "%02x", desc[i]);
                            }
                            build_id[nhdr.n_descsz * 2] = '\0';
                        }
                    }
                }
            }
        } else if (name && strcmp(name, ".gnu_debuglink") == 0) {
            Elf_Data *data = elf_getdata(section, NULL);

            if (data && data->d_buf) {
                debuglink = (char *)data->d_buf;
            }
        } else if (name && strcmp(name, ".gnu_debugaltlink") == 0) {
            Elf_Data *data = elf_getdata(section, NULL);

            if (data && data->d_buf) {
                debuglink = (char *)data->d_buf;
            }
        }
    }

    std::string build_id_str = build_id ? build_id : "";
    std::string debuglink_str = debuglink ? debuglink : "";

    if (build_id) {
        free(build_id);
    }

    return std::make_pair(build_id_str, debuglink_str);
}

// Read TLS information from the ELF file
TLSModuleInfo read_tls_info(Elf *elf, const std::string &path)
{
    TLSModuleInfo tls_info;
    tls_info.module_path = path;

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        return tls_info;
    }

    // Look for PT_TLS program header
    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) != 0) {
        return tls_info;
    }

    for (size_t i = 0; i < phnum; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != &phdr) {
            continue;
        }

        if (phdr.p_type == PT_TLS) {
            tls_info.tls_block_size = phdr.p_memsz;
            tls_info.tls_block_align = phdr.p_align;
            tls_info.tls_init_image_addr = phdr.p_vaddr;
            tls_info.tls_init_image_size = phdr.p_filesz;
            break;
        }
    }

    return tls_info;
}

// Check if ELF is PIE
bool is_elf_pie(Elf *elf)
{
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        return false;
    }
    return ehdr.e_type == ET_DYN;
}

// Get entry point
uint64_t get_elf_entry_point(Elf *elf)
{
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        return 0;
    }
    return ehdr.e_entry;
}

const ElfInfo read_elf_info(const std::string &elf_file_path, const int debug_info_level)
{
    int fd;
    Elf *elf;
    SymbolVector symbols;
    ElfInfo result;
    result.is_pie = false;
    result.entry_point = 0;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));
    }

    if (access(elf_file_path.c_str(), R_OK) == -1) {
        return result;
    }

    if ((fd = open(elf_file_path.c_str(), O_RDONLY, 0)) < 0) {
        throw std::invalid_argument("Error opening file: " + elf_file_path);
    }

    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        close(fd);
        throw std::runtime_error("Error reading ELF file: " + elf_file_path);
    }

    try {
        // Read basic ELF info
        result.is_pie = is_elf_pie(elf);
        result.entry_point = get_elf_entry_point(elf);

        // Read the symbol table
        process_symbol_tables(elf, symbols);

        // Read the build ID and debug link
        auto build_id_and_debug = read_build_id_and_filename(elf);
        result.build_id = build_id_and_debug.first;
        result.debuglink = build_id_and_debug.second;

        // Read TLS information
        result.tls_info = read_tls_info(elf, elf_file_path);

        if (debug_info_level > 1) {
            // Read the dwarf info
            process_dwarf_info(fd, symbols);
        }
    } catch (const std::exception &e) {
        elf_end(elf);
        close(fd);
        throw;
    }

    // We now set the runtime context fields
    for (auto &sym : symbols) {
        sym.backing_file = elf_file_path;
        sym.reference_file = elf_file_path;
        sym.reference_build_id = result.build_id;
        sym.is_external = false;
    }

    result.symbols = std::move(symbols);

    elf_end(elf);
    close(fd);

    return result;
}

SymbolVector collect_external_symbols(const std::string &debug_file_path,
                                        const std::string &reference_path,
                                        const std::string &build_id,
                                        const int debug_info_level)
{
    Elf *elf;
    int fd;
    SymbolVector symbols;

    // Initialize the ELF library
    if (elf_version(EV_CURRENT) == EV_NONE) {
        throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));
    }

    // Check if the debug file exists
    if (access(debug_file_path.c_str(), R_OK) == -1) {
        return symbols;
    }

    // Open the debug file
    if ((fd = open(debug_file_path.c_str(), O_RDONLY, 0)) < 0) {
        throw std::invalid_argument("Error opening file: " + debug_file_path);
    }

    // Check if the file is empty
    if (lseek(fd, 0, SEEK_END) == 0) {
        close(fd);
        return symbols;
    }

    // Reset file position
    lseek(fd, 0, SEEK_SET);

    // Read the ELF file
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        close(fd);
        throw std::runtime_error("Error reading ELF file: " + debug_file_path);
    }

    try {
        process_symbol_tables(elf, symbols);

        if (debug_info_level > 3) {
            // Read the dwarf info
            process_dwarf_info(fd, symbols);
        }
    } catch (const std::exception &e) {
        elf_end(elf);
        close(fd);
        throw;
    }

    // Set runtime context fields for external symbols
    for (auto &sym : symbols) {
        sym.backing_file = debug_file_path;
        sym.reference_file = reference_path;
        sym.reference_build_id = build_id;
        sym.is_external = true;
    }

    elf_end(elf);
    close(fd);

    return symbols;
}
