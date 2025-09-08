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

void process_plt_symbols(Elf *elf, SymbolVector &symbols)
{
    Elf_Scn *plt_scn = NULL;
    Elf_Scn *rela_plt_scn = NULL;
    Elf_Scn *dynsym_scn = NULL;
    GElf_Shdr shdr;
    char *name;
    GElf_Ehdr ehdr;

    if (!gelf_getehdr(elf, &ehdr)) {
        return;  // Can't read ELF header, skip PLT processing
    }

    // First, find the relevant sections: .plt, .rela.plt, and .dynsym
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (!name) {
            continue;
        }

        if (strcmp(name, ".plt") == 0) {
            plt_scn = scn;
        } else if (strcmp(name, ".rela.plt") == 0) {
            rela_plt_scn = scn;
        } else if (shdr.sh_type == SHT_DYNSYM) {
            dynsym_scn = scn;
        }
    }

    // If we don't have all the required sections, we can't process PLT symbols
    if (!plt_scn || !rela_plt_scn || !dynsym_scn) {
        return;
    }

    // Get PLT section info
    GElf_Shdr plt_shdr;
    if (gelf_getshdr(plt_scn, &plt_shdr) != &plt_shdr) {
        return;
    }

    // Get dynsym section info for later use
    GElf_Shdr dynsym_shdr;
    if (gelf_getshdr(dynsym_scn, &dynsym_shdr) != &dynsym_shdr) {
        return;
    }

    // Process .rela.plt relocations
    Elf_Data *rela_plt_data = elf_getdata(rela_plt_scn, NULL);
    if (!rela_plt_data) {
        return;
    }

    GElf_Shdr rela_plt_shdr;
    if (gelf_getshdr(rela_plt_scn, &rela_plt_shdr) != &rela_plt_shdr) {
        return;
    }

    Elf_Data *dynsym_data = elf_getdata(dynsym_scn, NULL);
    if (!dynsym_data) {
        return;
    }

    int rela_count = rela_plt_shdr.sh_size / rela_plt_shdr.sh_entsize;
    
    // Calculate PLT entry size based on architecture
    // For x86_64, each PLT entry is typically 16 bytes
    // The first entry is the PLT header, so skip it
    size_t plt_entry_size = 16;  // x86_64 default
    Dwarf_Addr plt_base = plt_shdr.sh_addr;
    Dwarf_Addr plt_entry_addr = plt_base + plt_entry_size; // Skip PLT header

    for (int i = 0; i < rela_count; ++i) {
        GElf_Rela rela;
        if (gelf_getrela(rela_plt_data, i, &rela) != &rela) {
            continue;
        }

        // Get the symbol index from the relocation
        int sym_index = GELF_R_SYM(rela.r_info);

        // Get the symbol from the dynamic symbol table
        GElf_Sym sym;
        if (gelf_getsym(dynsym_data, sym_index, &sym) != &sym) {
            continue;
        }

        // Get the symbol name
        const char *sym_name = elf_strptr(elf, dynsym_shdr.sh_link, sym.st_name);
        if (!sym_name || strlen(sym_name) == 0) {
            continue;
        }

        // Create PLT symbol name with "plt@" prefix
        std::string plt_symbol_name = "plt@" + std::string(sym_name);

        // Add the PLT symbol
        // PLT entries are typically 16 bytes on x86_64
        add_symbol_info(symbols, plt_symbol_name.c_str(), plt_entry_addr, plt_entry_addr + plt_entry_size);

        // Move to next PLT entry
        plt_entry_addr += plt_entry_size;
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

        // Read PLT symbols
        process_plt_symbols(elf, symbols);

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

        // Read PLT symbols
        process_plt_symbols(elf, symbols);

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
