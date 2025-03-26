//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/bind_vector.h>

#include "debug_sym_parser.h"

#define HAVE_DECL_BASENAME 1
#include <demangle.h>

#include <fcntl.h>
#include <gelf.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <libelf.h>

namespace nb = nanobind;

void add_symbol_info(SymbolVector &symbols, const char *name, const Dwarf_Addr low_pc, const Dwarf_Addr high_pc)
{
    SymbolInfo symbol_info;

    char *demangled_name = cplus_demangle_v3(name, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
    symbol_info.name = demangled_name ? demangled_name : name;
    symbol_info.low_pc = low_pc;
    symbol_info.high_pc = high_pc;

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
        throw std::runtime_error("Error reading ELF file: " + elf_file_path);
    }

    // Read the symbol table
    process_symbol_tables(elf, symbols);

    // Read the build ID
    std::pair<std::string, std::string> build_id_and_debug_file_path = read_build_id_and_filename(elf);
    std::string build_id = build_id_and_debug_file_path.first;
    std::string debug_file_path = build_id_and_debug_file_path.second;

    if (debug_info_level > 1) {
        // Read the dwarf info
        process_dwarf_info(fd, symbols);
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
        throw std::runtime_error("Error reading ELF file: " + debug_file_path);
    }

    // Read the symbol table
    process_symbol_tables(elf, symbols);

    if (debug_info_level > 3) {
        // Read the dwarf info
        process_dwarf_info(fd, symbols);
    }

    elf_end(elf);
    close(fd);

    return symbols;
}

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
}
