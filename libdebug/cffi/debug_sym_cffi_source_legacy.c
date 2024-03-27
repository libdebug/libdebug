//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <demangle.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct SymbolInfo
{
    char *name;
    unsigned long long high_pc;
    unsigned long long low_pc;
    struct SymbolInfo *next;
} SymbolInfo;

// Function to add new symbol info to the linked list
SymbolInfo *add_symbol_info(SymbolInfo **head, const char *name, Dwarf_Addr low_pc, Dwarf_Addr high_pc)
{
    SymbolInfo *new_node = (SymbolInfo *) malloc(sizeof(SymbolInfo));
    char *demangled_name = cplus_demangle_v3(name, DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
    new_node->name = demangled_name ? demangled_name : strdup(name);
    new_node->low_pc = low_pc;
    new_node->high_pc = high_pc;
    new_node->next = *head;
    *head = new_node;
    return new_node;
}

SymbolInfo *head = NULL;
char *build_id = NULL;
char *debug_file = NULL;

// Function to free the linked list
void free_symbol_info(SymbolInfo *head)
{
    while (head != NULL) {
        SymbolInfo *tmp = head;
        head = head->next;
        free(tmp->name);
        free(tmp);
    }
}

// Function to get the build ID
char *get_build_id()
{ 
    return build_id;
}

// Function to get the debug file path
char *get_debug_file()
{ 
    return debug_file; 
}

int process_die(Dwarf_Debug dbg, Dwarf_Die the_die)
{
    Dwarf_Error error;
    Dwarf_Half tag;
    char *die_name = 0;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Attribute *attrs;
    Dwarf_Signed attrcount, i;
    int is_formaddr = -1;

    if (dwarf_tag(the_die, &tag, &error) != DW_DLV_OK) {
        perror("Error getting DIE tag");
        return -1;
    }

    // Check if the DIE is a subprogram (function) or a variable
    if (tag == DW_TAG_subprogram || tag == DW_TAG_variable) {
        if (dwarf_diename(the_die, &die_name, &error) == DW_DLV_OK) {
            // Getting attributes of the DIE
            if (dwarf_attrlist(the_die, &attrs, &attrcount, &error) ==
                DW_DLV_OK) {
                for (i = 0; i < attrcount; ++i) {
                    Dwarf_Half attrcode;
                    if (dwarf_whatattr(attrs[i], &attrcode, &error) ==
                        DW_DLV_OK) {
                        if (attrcode == DW_AT_low_pc &&
                            dwarf_formaddr(attrs[i], &lowpc, &error) ==
                                DW_DLV_OK) {
                            continue;
                        } else if (attrcode == DW_AT_high_pc) {
                            if (dwarf_formaddr(attrs[i], &highpc, &error) ==
                                DW_DLV_OK) {
                                is_formaddr = 1;
                            } else {
                                if (dwarf_formudata(attrs[i], &highpc,
                                                    &error) == DW_DLV_OK) {
                                    is_formaddr = 0;
                                }
                            }
                        }
                    }
                    dwarf_dealloc(dbg, attrs[i], DW_DLA_ATTR);
                }
                dwarf_dealloc(dbg, attrs, DW_DLA_LIST);
            }
        }

        if (lowpc != 0 && highpc != 0 && die_name) {
            if (is_formaddr == 0) {
                highpc += lowpc;
            }
            add_symbol_info(&head, die_name, lowpc, highpc);
        }
        if (die_name) {
            dwarf_dealloc(dbg, die_name, DW_DLA_STRING);
        }
    }
    return 0;
}

// Function for symbol names
int help_symbol_names(Dwarf_Debug dbg)
{
    Dwarf_Error err;
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Die no_die = 0, cu_die, child_die, sibling_die;

    // Loop through all the compilation units
    while (dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp,
                                &abbrev_offset, &address_size, &next_cu_header,
                                &err) == DW_DLV_OK) {
        // Get the DIE for the current compilation unit
        if (dwarf_siblingof(dbg, no_die, &cu_die, &err) != DW_DLV_OK) {
            perror("Error getting sibling of CU");
            return -1;
        }

        if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_OK) {
            while (child_die != NULL) {
                if (process_die(dbg, child_die) == -1) {
                    return -1;
                }
                // Get the next DIE (sibling)
                if (dwarf_siblingof(dbg, child_die, &sibling_die, &err) !=
                    DW_DLV_OK) {
                    // If there's no sibling, we're done with this level
                    dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
                    break;
                }
                // Deallocate the current DIE and move to the sibling
                dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
                child_die = sibling_die;
            }
        }
        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
    }
    return 0;
}

void retrieve_from_dwarf(int fd)
{
    Dwarf_Debug dbg;
    Dwarf_Error err;

    // Initialize the DWARF library
    if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        perror("Failed DWARF initialization");
        return;
    }

    if (help_symbol_names(dbg) == -1) {
        return;
    }
    dwarf_finish(dbg, &err);
}

// Function to collect external symbols from the debug file
SymbolInfo *collect_external_symbols(const char *debug_file_path, int debug_info_level)
{
    Elf *elf;
    int fd;

    // Initialize the ELF library
    if (elf_version(EV_CURRENT) == EV_NONE) {
        perror("Failed to initialize libelf");
        return NULL;
    }

    // Check if the debug file exists
    if (access(debug_file_path, R_OK) != 0) {
        return NULL;
    }

    // Open the ELF file
    fd = open(debug_file_path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open ELF file");
        return NULL;
    }

    // Initialize the ELF
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        perror("Failed to initialize the ELF descriptor");
        close(fd);
        return NULL;
    }

    process_symbol_tables(elf);

    if (debug_info_level > 3) {
        retrieve_from_dwarf(fd);
    }

    elf_end(elf);
    close(fd);

    return head;
}

// Function to process the symbol tables
void process_symbol_tables(Elf *elf)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    head = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) continue;
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
                        add_symbol_info(&head, name, low_pc, high_pc);
                    };
                }
            }
        }
    }
}

void retrieve_build_id(Elf *elf)
{
    GElf_Shdr shdr;
    GElf_Ehdr ehdr;  // ELF header
    Elf_Scn *section = NULL;

    if (!gelf_getehdr(elf, &ehdr)) {
        perror("Error reading ELF header");
        return;
    }

    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (!gelf_getshdr(section, &shdr)) {
            // Error reading section header
            continue;
        }

        if (shdr.sh_type == SHT_NOTE) {
            char *name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
            if (name && strcmp(name, ".note.gnu.build-id") == 0) {
                Elf_Data *data = elf_getdata(section, NULL);
                if (data) {
                    GElf_Nhdr nhdr;
                    size_t offset = 0;
                    size_t name_offset, desc_offset;

                    while ((offset =
                                gelf_getnote(data, offset, &nhdr, &name_offset,
                                             &desc_offset)) != 0) {
                        if (nhdr.n_type == NT_GNU_BUILD_ID) {
                            build_id = malloc(nhdr.n_descsz * 2 + 1);
                            unsigned char *desc =
                                (unsigned char *)data->d_buf + desc_offset;
                            for (size_t i = 0; i < nhdr.n_descsz; i++) {
                                sprintf(build_id + (i * 2), "%02x", desc[i]);
                            }
                            build_id[nhdr.n_descsz * 2] = '\0';
                        }
                    }
                }
            }
        }
    }
}

// Function to retrieve the debug file path from the gnu_debuglink and
// gnu_debugaltlink sections
void retrieve_debug_filename(Elf *elf)
{
    Elf_Scn *section = NULL;
    GElf_Ehdr ehdr;  // ELF header
    GElf_Shdr shdr;  // Section header

    if (!gelf_getehdr(elf, &ehdr)) {
        // Error reading ELF header
        perror("Error reading ELF header");
        return;
    }

    while ((section = elf_nextscn(elf, section)) != NULL) {
        if (!gelf_getshdr(section, &shdr)) {
            // Error reading section header
            continue;
        }

        char *name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (name && (strcmp(name, ".gnu_debuglink") == 0 ||
                     strcmp(name, ".gnu_debugaltlink") == 0)) {
            // Found the debug link section
            Elf_Data *data = elf_getdata(section, NULL);
            if (data && data->d_buf) {
                debug_file = strdup((char *)data->d_buf);
            }
        }
    }
}

// Function to read the symbol table, build ID, gnu_debuglink, and
// gnu_debugaltlink
SymbolInfo *read_elf_info(const char *elf_file_path, int debug_info_level)
{
    int fd;
    Elf *elf;
    head = NULL;
    build_id = NULL;
    debug_file = NULL;

    // Initialize the ELF library
    if (elf_version(EV_CURRENT) == EV_NONE) {
        perror("Failed to initialize libelf");
        return NULL;
    }

    // Check if the debug file exists
    if (access(elf_file_path, R_OK) != 0) {
        return NULL;
    }

    // Open the ELF file
    fd = open(elf_file_path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open ELF file");
        perror(elf_file_path);
        return NULL;
    }

    // Initialize the ELF
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        perror("Failed to initialize the ELF descriptor");
        close(fd);
        return NULL;
    }

    // read the symbol table
    process_symbol_tables(elf);

    // read the build ID
    retrieve_build_id(elf);

    // read the debug file path
    retrieve_debug_filename(elf);

    if (debug_info_level > 1) {
        retrieve_from_dwarf(fd);
    }

    elf_end(elf);
    close(fd);
    return head;
}
