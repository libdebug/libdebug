//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
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
#include <map>
#include <algorithm>
#include <climits>
#include <cstdint>

void add_symbol_info(SymbolVector &symbols, const char *name, const Dwarf_Addr low_pc, const Dwarf_Addr high_pc)
{
    SymbolInfo symbol_info;

    symbol_info.low_pc = low_pc;
    symbol_info.high_pc = high_pc;

#ifdef HAS_LIBIBERTY
    char *demangled_name = cplus_demangle_v3(name, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);

    if (demangled_name) {
        // We push both the demangled name and the original name
        symbol_info.name = demangled_name;
        symbols.push_back(symbol_info);
    }
#endif

    // Push the original name
    symbol_info.name = name;
    symbols.push_back(symbol_info);
};

// Only use complete, file-backed data with the expected libelf representation.
static Elf_Data *section_data(Elf *elf, Elf_Scn *scn, const GElf_Shdr &sh, Elf_Type type)
{
    size_t file_size = 0;
    if (!elf_rawfile(elf, &file_size) || sh.sh_type == SHT_NOBITS ||
        sh.sh_offset > file_size || sh.sh_size > file_size - sh.sh_offset) return nullptr;
    Elf_Data *data = elf_getdata(scn, nullptr);
    if (!data || !data->d_buf || data->d_off != 0 || data->d_type != type ||
        data->d_size != sh.sh_size) return nullptr;
    return data;
}

static Elf_Data *table_data(Elf *elf, Elf_Scn *scn, const GElf_Shdr &sh, Elf_Type type)
{
    const size_t entry_size = gelf_fsize(elf, type, 1, EV_CURRENT);
    if (!entry_size || sh.sh_entsize != entry_size || sh.sh_size % entry_size) return nullptr;
    return section_data(elf, scn, sh, type);
}

static Elf_Data *string_table(Elf *elf, size_t index)
{
    Elf_Scn *scn = elf_getscn(elf, index);
    GElf_Shdr sh{};
    if (!scn || !gelf_getshdr(scn, &sh) || sh.sh_type != SHT_STRTAB) return nullptr;
    return section_data(elf, scn, sh, ELF_T_BYTE);
}

static const char *symbol_name(Elf_Data *strings, size_t offset)
{
    if (!strings || offset >= strings->d_size) return nullptr;
    const char *name = static_cast<const char *>(strings->d_buf) + offset;
    if (!*name || !memchr(name, '\0', strings->d_size - offset)) return nullptr;
    return name;
}

// A GOT address must describe a complete slot in an allocated section.
static bool allocated_address(Elf *elf, GElf_Addr address, size_t size)
{
    for (Elf_Scn *scn = elf_nextscn(elf, nullptr); scn; scn = elf_nextscn(elf, scn)) {
        GElf_Shdr sh{};
        if (gelf_getshdr(scn, &sh) && (sh.sh_flags & SHF_ALLOC) && address >= sh.sh_addr &&
            address - sh.sh_addr <= sh.sh_size && size <= sh.sh_size - (address - sh.sh_addr)) return true;
    }
    return false;
}

static bool pltgot_address(Elf *elf, GElf_Addr &address)
{
    bool found = false;
    for (Elf_Scn *scn = elf_nextscn(elf, nullptr); scn; scn = elf_nextscn(elf, scn)) {
        GElf_Shdr sh{};
        if (!gelf_getshdr(scn, &sh) || sh.sh_type != SHT_DYNAMIC) continue;
        Elf_Data *data = table_data(elf, scn, sh, ELF_T_DYN);
        if (!data) continue;
        const size_t count = std::min<size_t>(data->d_size / sh.sh_entsize, INT_MAX);
        for (size_t i = 0; i < count; ++i) {
            GElf_Dyn dyn{};
            if (!gelf_getdyn(data, static_cast<int>(i), &dyn)) continue;
            if (dyn.d_tag == DT_NULL) break;
            if (dyn.d_tag != DT_PLTGOT) continue;
            if (dyn.d_un.d_ptr > UINT32_MAX || !allocated_address(elf, dyn.d_un.d_ptr, 12) ||
                (found && address != dyn.d_un.d_ptr)) return false;
            address = dyn.d_un.d_ptr;
            found = true;
        }
    }
    return found;
}

static uint32_t read_le32(const unsigned char *p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

static bool relative_address(GElf_Addr base, int64_t displacement, GElf_Addr &target)
{
    if (displacement < 0) {
        const uint64_t magnitude = static_cast<uint64_t>(-displacement);
        if (base < magnitude) return false;
        target = base - magnitude;
    } else {
        if (base > UINT64_MAX - static_cast<uint64_t>(displacement)) return false;
        target = base + displacement;
    }
    return true;
}

// Decode only the supported entry forms, never search inside arbitrary code.
static bool plt_target(const unsigned char *p, size_t size, GElf_Addr pc, int machine,
                       bool have_pltgot, GElf_Addr pltgot, GElf_Addr &target)
{
    if (machine == EM_X86_64 || machine == EM_386) {
        size_t offset = 0;
        const unsigned char endbr = machine == EM_X86_64 ? 0xfa : 0xfb;
        if (size >= 4 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == endbr) offset = 4;
        if (offset < size && p[offset] == 0xf2) ++offset; // BND
        if (size - offset < 6 || p[offset] != 0xff) return false;
        const uint32_t operand = read_le32(p + offset + 2);
        if (p[offset + 1] == 0x25) {
            if (machine == EM_386) {
                target = operand;
                return true;
            }
            const int64_t displacement = operand & 0x80000000U ? int64_t(operand) - 0x100000000LL : operand;
            return relative_address(pc + offset + 6, displacement, target);
        }
        if (machine == EM_386 && p[offset + 1] == 0xa3 && have_pltgot) {
            target = static_cast<uint32_t>(pltgot + operand);
            return true;
        }
        return false;
    }
    if (machine == EM_AARCH64 && size >= 16) {
        const uint32_t adrp = read_le32(p), ldr = read_le32(p + 4);
        const uint32_t add = read_le32(p + 8), branch = read_le32(p + 12);
        if ((adrp & 0x9f00001fU) != 0x90000010U || (ldr & 0xffc003ffU) != 0xf9400211U ||
            (add & 0xffc003ffU) != 0x91000210U || branch != 0xd61f0220U) return false;
        const uint32_t slot_offset = ((ldr >> 10) & 0xfff) * 8;
        if (((add >> 10) & 0xfff) != slot_offset) return false;
        const uint32_t immediate = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2);
        const int64_t pages = immediate & 0x100000 ? int64_t(immediate) - 0x200000 : immediate;
        return relative_address(pc & ~GElf_Addr(0xfff), pages * 4096 + slot_offset, target);
    }
    return false;
}

void process_plt_relocations(Elf *elf, const GElf_Ehdr &ehdr, SymbolVector &symbols)
{
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) return;
    unsigned jump_slot, glob_dat;
    switch (ehdr.e_machine) {
        case EM_X86_64: jump_slot = R_X86_64_JUMP_SLOT; glob_dat = R_X86_64_GLOB_DAT; break;
        case EM_386: jump_slot = R_386_JMP_SLOT; glob_dat = R_386_GLOB_DAT; break;
        case EM_AARCH64: jump_slot = R_AARCH64_JUMP_SLOT; glob_dat = R_AARCH64_GLOB_DAT; break;
        default: return;
    }
    const size_t slot_size = ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? 8 : 4;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) return;
    Elf_Data *section_names = string_table(elf, shstrndx);
    struct PLTSection {
        GElf_Shdr sh;
        Elf_Data *data;
    };
    std::map<std::string, PLTSection> sections;
    struct Relocation {
        std::string name;
        bool jump_slot;
        bool matched = false;
        bool ambiguous = false;
    };
    std::map<GElf_Addr, Relocation> relocations;
    for (Elf_Scn *scn = elf_nextscn(elf, nullptr); scn; scn = elf_nextscn(elf, scn)) {
        GElf_Shdr sh{};
        if (!gelf_getshdr(scn, &sh)) continue;
        const char *name = symbol_name(section_names, sh.sh_name);
        if (sh.sh_type == SHT_PROGBITS && (sh.sh_flags & SHF_EXECINSTR) && name &&
            (strcmp(name, ".plt") == 0 || strcmp(name, ".plt.sec") == 0 || strcmp(name, ".plt.got") == 0)) {
            Elf_Data *data = section_data(elf, scn, sh, ELF_T_BYTE);
            if (data && sh.sh_addr <= UINT64_MAX - sh.sh_size) sections[name] = {sh, data};
        }
        if (sh.sh_type != SHT_REL && sh.sh_type != SHT_RELA) continue;
        Elf_Data *data = table_data(elf, scn, sh, sh.sh_type == SHT_RELA ? ELF_T_RELA : ELF_T_REL);
        Elf_Scn *sym_scn = elf_getscn(elf, sh.sh_link);
        GElf_Shdr sym_sh{};
        if (!data || !sym_scn || !gelf_getshdr(sym_scn, &sym_sh) ||
            (sym_sh.sh_type != SHT_DYNSYM && sym_sh.sh_type != SHT_SYMTAB)) continue;
        Elf_Data *sym_data = table_data(elf, sym_scn, sym_sh, ELF_T_SYM);
        Elf_Data *strings = string_table(elf, sym_sh.sh_link);
        if (!sym_data || !strings) continue;
        const size_t count = std::min<size_t>(data->d_size / sh.sh_entsize, INT_MAX);
        for (size_t i = 0; i < count; ++i) {
            GElf_Addr address;
            GElf_Xword info;
            if (sh.sh_type == SHT_RELA) {
                GElf_Rela rel{};
                if (!gelf_getrela(data, static_cast<int>(i), &rel)) continue;
                address = rel.r_offset;
                info = rel.r_info;
            } else {
                GElf_Rel rel{};
                if (!gelf_getrel(data, static_cast<int>(i), &rel)) continue;
                address = rel.r_offset;
                info = rel.r_info;
            }
            if ((GELF_R_TYPE(info) != jump_slot && GELF_R_TYPE(info) != glob_dat) || address > UINT64_MAX - slot_size ||
                !allocated_address(elf, address, slot_size)) continue;
            const size_t index = GELF_R_SYM(info);
            if (index > INT_MAX || index >= sym_data->d_size / sym_sh.sh_entsize) continue;
            GElf_Sym sym{};
            if (!gelf_getsym(sym_data, static_cast<int>(index), &sym)) continue;
            const char *symbol = symbol_name(strings, sym.st_name);
            if (!symbol) continue;
            auto [it, inserted] = relocations.emplace(address, Relocation{symbol, GELF_R_TYPE(info) == jump_slot});
            if (!inserted && (it->second.name != symbol ||
                              it->second.jump_slot != (GELF_R_TYPE(info) == jump_slot))) {
                it->second.ambiguous = true;
            }
        }
    }
    for (const auto &[address, rel] : relocations) {
        if (!rel.ambiguous && rel.jump_slot) {
            add_symbol_info(symbols, (rel.name + "@got.plt").c_str(), address, address + slot_size);
        }
    }
    GElf_Addr pltgot = 0;
    const bool have_pltgot = ehdr.e_machine == EM_386 && pltgot_address(elf, pltgot);
    // Prefer the callable CET entry over a lazy entry referencing the same slot.
    for (const char *name : {".plt.sec", ".plt.got", ".plt"}) {
        auto section = sections.find(name);
        if (section == sections.end()) continue;
        const auto &plt = section->second;
        const size_t header = strcmp(name, ".plt") == 0 ? (ehdr.e_machine == EM_AARCH64 ? 32 : 16) : 0;
        // GNU x86 .plt.got has 8-byte entries, or 16-byte entries for CET.
        // Its entry size is meaningful (unlike the historical i386 .plt value of 4).
        const bool got_section = strcmp(name, ".plt.got") == 0;
        const size_t entry = got_section && ehdr.e_machine != EM_AARCH64 ? plt.sh.sh_entsize : 16;
        if (entry != 8 && entry != 16) continue;
        if (plt.data->d_size < header) continue;
        const auto *bytes = static_cast<const unsigned char *>(plt.data->d_buf);
        for (size_t offset = header; entry <= plt.data->d_size - offset; offset += entry) {
            GElf_Addr target;
            const GElf_Addr pc = plt.sh.sh_addr + offset;
            if (!plt_target(bytes + offset, entry, pc, ehdr.e_machine, have_pltgot, pltgot, target)) continue;
            auto it = relocations.find(target);
            if (it == relocations.end() || it->second.ambiguous || it->second.matched) continue;
            auto &rel = it->second;
            add_symbol_info(symbols, (rel.name + "@plt").c_str(), pc, pc + entry);
            if (!rel.jump_slot) {
                add_symbol_info(symbols, (rel.name + "@got").c_str(), target, target + slot_size);
            }
            rel.matched = true;
        }
    }
}

void process_symbol_tables(Elf *elf, SymbolVector &symbols)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            data = table_data(elf, scn, shdr, ELF_T_SYM);
            if (!data || !string_table(elf, shdr.sh_link)) continue;
            int count = std::min<size_t>(data->d_size / shdr.sh_entsize, INT_MAX);

            for (int i = 0; i < count; ++i) {
                GElf_Sym sym{};
                if (!gelf_getsym(data, i, &sym)) continue;

                const char *name = symbol_name(string_table(elf, shdr.sh_link), sym.st_name);

                if (name) {
                    Dwarf_Addr low_pc = sym.st_value;
                    Dwarf_Addr high_pc = sym.st_value + sym.st_size;

                    if (high_pc != 0 && high_pc != 0) {
                        add_symbol_info(symbols, name, low_pc, high_pc);
                    }
                }
            }
        }
    }
}

std::pair<const std::string, const std::string> read_build_id_and_filename(Elf *elf)
{
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;  // ELF header
    Elf_Scn *section = NULL;
    char *build_id = NULL, *debuglink = NULL;

    if (!gelf_getehdr(elf, &ehdr)) {
        throw std::runtime_error("Failed to read ELF header");
    }

    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (!gelf_getshdr(section, &shdr)) {
            // Error reading section header
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

const ElfInfo read_elf_info(const std::string &elf_file_path, const int debug_info_level)
{
    int fd;
    Elf *elf;
    SymbolVector symbols;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        throw std::runtime_error("ELF library initialization failed: " + std::string(elf_errmsg(-1)));
    }

    if (access(elf_file_path.c_str(), R_OK) == -1) {
        return {"", "", symbols};
    }

    if ((fd = open(elf_file_path.c_str(), O_RDONLY, 0)) < 0) {
        throw std::invalid_argument("Error opening file: " + elf_file_path);
    }

    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        close(fd);
        throw std::runtime_error("Error reading ELF file: " + elf_file_path);
    }

    std::pair<std::string, std::string> build_id_and_debug_file_path;
    std::string build_id;
    std::string debug_file_path;

    try {
        // Read the symbol table
        process_symbol_tables(elf, symbols);

        // Process PLT relocations to add symbols like foo@plt
        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr)) {
            process_plt_relocations(elf, ehdr, symbols);
        }

        // Read the build ID
        build_id_and_debug_file_path = read_build_id_and_filename(elf);
        build_id = build_id_and_debug_file_path.first;
        debug_file_path = build_id_and_debug_file_path.second;

        if (debug_info_level > 1) {
            // Read the dwarf info
            process_dwarf_info(fd, symbols);
        }
    } catch (const std::exception &e) {
        elf_end(elf);
        close(fd);
        throw;
    }

    elf_end(elf);
    close(fd);

    return {build_id, debug_file_path, symbols};
}

SymbolVector collect_external_symbols(const std::string &debug_file_path, const int debug_info_level)
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
        // The debug file does not exist on this system
        return symbols;
    }

    // Open the debug file
    if ((fd = open(debug_file_path.c_str(), O_RDONLY, 0)) < 0) {
        throw std::invalid_argument("Error opening file: " + debug_file_path);
    }

    // Check if the file is empty
    if (lseek(fd, 0, SEEK_END) == 0) {
        // The debug file is empty
        close(fd);
        return symbols;
    }

    // Read the ELF file
    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
        close(fd);
        throw std::runtime_error("Error reading ELF file: " + debug_file_path);
    }

    // Read the symbol table
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

    elf_end(elf);
    close(fd);

    return symbols;
}
