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



void process_plt_relocations(Elf *elf,
                             const GElf_Ehdr &ehdr,
                             SymbolVector    &symbols)
{
    /* Cache all PLT-related sections */
    struct PLTSection {
        Elf_Scn  *scn;
        GElf_Shdr shdr;
        std::string name;
        std::size_t entry_count;  // Track entries per section
    };
    
    std::map<std::string, PLTSection> plt_sections;
    
    // First pass: find all PLT sections
    for (Elf_Scn *sec = elf_nextscn(elf, nullptr); sec;
         sec = elf_nextscn(elf, sec))
    {
        GElf_Shdr sh;
        if (gelf_getshdr(sec, &sh) != &sh)          continue;
        if (sh.sh_type != SHT_PROGBITS)            continue;
        if (!(sh.sh_flags & SHF_EXECINSTR))        continue;

        const char *n = elf_strptr(elf, ehdr.e_shstrndx, sh.sh_name);
        if (n && strncmp(n, ".plt", 4) == 0) {
            plt_sections[n] = {sec, sh, n, 0};
        }
    }

    /* Architecture and section-specific parameters */
    auto get_plt_params = [&](const std::string& plt_name) 
        -> std::pair<std::size_t, std::size_t> {
        
        std::size_t header_size = 0;
        std::size_t entry_size = 16;  // default
        
        if (plt_name == ".plt") {
            // Traditional PLT with header
            switch (ehdr.e_machine) {
                case EM_386:     header_size = 16; entry_size = 16; break;
                case EM_X86_64:  header_size = 16; entry_size = 16; break;
                case EM_AARCH64: header_size = 32; entry_size = 16; break;
                default:         header_size = 16; entry_size = 16; break;
            }
        } else if (plt_name == ".plt.sec") {
            // Secondary PLT - no header
            header_size = 0;
            entry_size = 16;
        } else if (plt_name == ".plt.got") {
            // Direct GOT PLT - no header, smaller entries
            header_size = 0;
            entry_size = (ehdr.e_machine == EM_X86_64) ? 8 : 16;
        }
        
        return {header_size, entry_size};
    };

    const std::size_t got_slot_sz = (ehdr.e_ident[EI_CLASS] == ELFCLASS64) ? 8 : 4;

    // Map to track which PLT section each symbol belongs to
    struct RelocationInfo {
        std::string symbol_name;
        Dwarf_Addr got_addr;
        std::string plt_section;
    };
    std::vector<RelocationInfo> relocations;

    /* Second pass: collect all PLT relocations */
    for (Elf_Scn *sec = elf_nextscn(elf, nullptr); sec;
         sec = elf_nextscn(elf, sec))
    {
        GElf_Shdr sh;
        if (gelf_getshdr(sec, &sh) != &sh)                       continue;
        if (sh.sh_type != SHT_RELA && sh.sh_type != SHT_REL)     continue;

        const char *secname = elf_strptr(elf, ehdr.e_shstrndx, sh.sh_name);
        if (!secname || strncmp(secname, ".rel", 4) != 0)        continue;
        
        // Skip if not a PLT relocation section
        if (!strstr(secname, ".plt")) continue;

        /* Get dynsym and relocation data */
        Elf_Scn *dynsym_sec = elf_getscn(elf, sh.sh_link);
        if (!dynsym_sec) continue;

        GElf_Shdr dynsym_sh;
        if (!gelf_getshdr(dynsym_sec, &dynsym_sh))               continue;

        Elf_Data *dynsym_data = elf_getdata(dynsym_sec, nullptr);
        Elf_Data *rel_data    = elf_getdata(sec,         nullptr);
        if (!dynsym_data || !rel_data)                           continue;

        const std::size_t nrel = sh.sh_size / sh.sh_entsize;

        for (std::size_t idx = 0; idx < nrel; ++idx) {
            /* Extract relocation fields */
            std::size_t sym_idx;
            Dwarf_Addr  r_off;

            if (sh.sh_type == SHT_RELA) {
                GElf_Rela rela;
                gelf_getrela(rel_data, idx, &rela);
                sym_idx = GELF_R_SYM(rela.r_info);
                r_off   = rela.r_offset;
            } else {
                GElf_Rel rel;
                gelf_getrel(rel_data, idx, &rel);
                sym_idx = GELF_R_SYM(rel.r_info);
                r_off   = rel.r_offset;
            }

            /* Get symbol name */
            GElf_Sym dsym;
            gelf_getsym(dynsym_data, sym_idx, &dsym);
            const char *name = elf_strptr(elf, dynsym_sh.sh_link, dsym.st_name);
            if (!name || !*name) continue;

            relocations.push_back({name, r_off, ""});
        }
    }

    // Now we need to determine which PLT section each symbol uses
    // This typically requires analyzing the GOT entries and PLT code
    
    // For .plt.got entries, check if GOT entry points directly to function
    auto plt_got_it = plt_sections.find(".plt.got");
    if (plt_got_it != plt_sections.end()) {
        Elf_Data *got_data = elf_getdata(plt_got_it->second.scn, nullptr);
        if (got_data) {
            // Analyze .plt.got entries to match with relocations
            auto [hdr_sz, ent_sz] = get_plt_params(".plt.got");
            std::size_t num_entries = (plt_got_it->second.shdr.sh_size - hdr_sz) / ent_sz;
            
            // Match relocations that use .plt.got based on relocation type or other heuristics
            for (auto& rel : relocations) {
                // This is where you'd check if this relocation uses .plt.got
                // For now, let's use a simple heuristic: __cxa_finalize often uses .plt.got
                if (rel.symbol_name == "__cxa_finalize") {
                    rel.plt_section = ".plt.got";
                    
                    // Record GOT entry
                    std::string got_name = rel.symbol_name + "@got";
                    add_symbol_info(symbols, got_name.c_str(), rel.got_addr, rel.got_addr + got_slot_sz);
                    
                    // Record PLT entry in .plt.got
                    Dwarf_Addr plt_addr = plt_got_it->second.shdr.sh_addr;
                    std::string plt_name = rel.symbol_name + "@plt";
                    add_symbol_info(symbols, plt_name.c_str(), plt_addr, plt_addr + ent_sz);
                }
            }
        }
    }

    // For .plt.sec entries
    auto plt_sec_it = plt_sections.find(".plt.sec");
    if (plt_sec_it != plt_sections.end()) {
        auto [hdr_sz, ent_sz] = get_plt_params(".plt.sec");
        std::size_t entry_idx = 0;
        
        for (auto& rel : relocations) {
            if (rel.plt_section.empty()) {  // Not yet assigned
                rel.plt_section = ".plt.sec";
                
                // Record GOT entry
                std::string got_name = rel.symbol_name + "@got.plt";
                add_symbol_info(symbols, got_name.c_str(), rel.got_addr, rel.got_addr + got_slot_sz);
                
                // Record PLT entry in .plt.sec
                Dwarf_Addr plt_addr = plt_sec_it->second.shdr.sh_addr + entry_idx * ent_sz;
                std::string plt_name = rel.symbol_name + "@plt";
                add_symbol_info(symbols, plt_name.c_str(), plt_addr, plt_addr + ent_sz);
                
                entry_idx++;
            }
        }
    }
    
    // Traditional .plt entries (if any remain)
    auto plt_it = plt_sections.find(".plt");
    if (plt_it != plt_sections.end()) {
        auto [hdr_sz, ent_sz] = get_plt_params(".plt");
        std::size_t entry_idx = 0;
        
        for (auto& rel : relocations) {
            if (rel.plt_section.empty()) {  // Not yet assigned
                rel.plt_section = ".plt";
                
                // Record GOT entry
                std::string got_name = rel.symbol_name + "@got.plt";
                add_symbol_info(symbols, got_name.c_str(), rel.got_addr, rel.got_addr + got_slot_sz);
                
                // Record PLT entry in .plt (after header)
                Dwarf_Addr plt_addr = plt_it->second.shdr.sh_addr + hdr_sz + entry_idx * ent_sz;
                std::string plt_name = rel.symbol_name + "@plt";
                add_symbol_info(symbols, plt_name.c_str(), plt_addr, plt_addr + ent_sz);
                
                entry_idx++;
            }
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
            data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;

            for (int i = 0; i < count; ++i) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);

                const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);

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
