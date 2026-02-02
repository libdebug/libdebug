//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2026 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser.h"
#include <memory>

#ifdef HAS_LIBIBERTY
    #define HAVE_DECL_BASENAME 1
    #include <demangle.h>
#endif

void process_die(Dwarf_Debug dbg, Dwarf_Die the_die, SymbolVector &symbols)
{
    Dwarf_Error error;
    Dwarf_Half tag;
    char *die_name = 0;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Attribute *attrs;
    Dwarf_Signed attrcount, i;
    int is_formaddr = -1;

    if (dwarf_tag(the_die, &tag, &error) != DW_DLV_OK) {
        throw std::runtime_error("Failed to get the tag of the DIE");
    }

    // Determine symbol type based on DWARF tag
    SymbolType sym_type = SymbolType::NOTYPE;
    bool is_tls = false;

    switch (tag) {
        case DW_TAG_subprogram:
            sym_type = SymbolType::FUNC;
            break;
        case DW_TAG_variable:
            sym_type = SymbolType::OBJECT;
            break;
        default:
            // We only process functions and variables from DWARF
            return;
    }

    // Check for thread-local storage
    if (tag == DW_TAG_variable) {
        Dwarf_Attribute tls_attr;
        if (dwarf_attr(the_die, DW_AT_location, &tls_attr, &error) == DW_DLV_OK) {
            Dwarf_Half form;
            if (dwarf_whatform(tls_attr, &form, &error) == DW_DLV_OK) {
                // Check if it's a TLS variable by looking at the location expression
                Dwarf_Block *block_ptr;
                if (dwarf_formblock(tls_attr, &block_ptr, &error) == DW_DLV_OK && block_ptr->bl_len > 0) {
                    // Check first byte for TLS-related DWARF location opcodes
                    unsigned char first_op = ((unsigned char *)block_ptr->bl_data)[0];
                    if (first_op == DW_OP_form_tls_address ||      // DWARF 3+ standard (0x9b)
                        first_op == DW_OP_GNU_push_tls_address) {  // GNU extension (0xe0)
                        is_tls = true;
                        sym_type = SymbolType::TLS;
                    }
                }
            }
            dwarf_dealloc(dbg, tls_attr, DW_DLA_ATTR);
        }
    }

    if (dwarf_diename(the_die, &die_name, &error) == DW_DLV_OK) {
        // Getting attributes of the DIE
        if (dwarf_attrlist(the_die, &attrs, &attrcount, &error) == DW_DLV_OK) {
            for (i = 0; i < attrcount; ++i) {
                Dwarf_Half attrcode;

                if (dwarf_whatattr(attrs[i], &attrcode, &error) == DW_DLV_OK) {
                    if (attrcode == DW_AT_low_pc && dwarf_formaddr(attrs[i], &lowpc, &error) == DW_DLV_OK) {
                        continue;
                    }

                    if (attrcode == DW_AT_high_pc) {
                        if (dwarf_formaddr(attrs[i], &highpc, &error) == DW_DLV_OK) {
                            is_formaddr = 1;
                        } else if (dwarf_formudata(attrs[i], &highpc, &error) == DW_DLV_OK) {
                            is_formaddr = 0;
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

        symbols.emplace_back();
        SymbolInfo &sym = symbols.back();
        sym.name = die_name;
        sym.demangled_name = demangle_symbol(die_name);
        sym.low_pc = lowpc;
        sym.high_pc = highpc;
        sym.type = sym_type;
        sym.binding = SymbolBinding::GLOBAL;  // DWARF doesn't have binding info directly
        sym.visibility = SymbolVisibility::DEFAULT;
        sym.section_index = 0;
        sym.is_tls = is_tls;
        sym.tls_offset = is_tls ? static_cast<int64_t>(lowpc) : 0;
        sym.tls_module_id = -1;
        sym.is_plt = false;
        sym.is_got = false;
    }

    if (die_name) {
        dwarf_dealloc(dbg, die_name, DW_DLA_STRING);
    }
}

void dwarf_retrieve_symbol_names(Dwarf_Debug dbg, SymbolVector &symbols)
{
    Dwarf_Unsigned abbrev_offset;
    Dwarf_Half address_size;
    Dwarf_Half version_stamp;
    Dwarf_Half offset_size;
    Dwarf_Half extension_size;
    Dwarf_Sig8 signature;
    Dwarf_Unsigned typeoffset;
    Dwarf_Unsigned next_cu_header;
    Dwarf_Half header_cu_type;
    Dwarf_Bool is_info = true;
    Dwarf_Die cu_die = NULL;
    Dwarf_Die child_die = NULL;
    Dwarf_Die no_die = NULL;
    Dwarf_Error err;
    Dwarf_Die sibling_die = NULL;
    Dwarf_Unsigned cu_header_length;

    // Loop through all the compilation units
    while (dwarf_next_cu_header_d(dbg, is_info, &cu_header_length,
                                  &version_stamp, &abbrev_offset, &address_size,
                                  &offset_size, &extension_size, &signature,
                                  &typeoffset, &next_cu_header, &header_cu_type,
                                  &err) == DW_DLV_OK) {
        // Get the DIE for the current compilation unit
        if (dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &err) != DW_DLV_OK) {
            continue;  // Skip this CU if we can't get the DIE
        }

        if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_OK) {
            while (child_die != NULL) {
                process_die(dbg, child_die, symbols);

                // Get the next DIE (sibling)
                int res = dwarf_siblingof_b(dbg, child_die, is_info, &sibling_die, &err);
                dwarf_dealloc(dbg, child_die, DW_DLA_DIE);

                if (res != DW_DLV_OK) {
                    child_die = NULL;
                } else {
                    child_die = sibling_die;
                }
            }
        }

        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
    }
}

void process_dwarf_info(const int fd, SymbolVector &symbols)
{
    Dwarf_Debug dbg;
    Dwarf_Error err;

    // Initialize the DWARF library
    if (dwarf_init_b(fd, DW_DLA_WEAK, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        // DWARF info may not be present, which is fine
        return;
    }

    try {
        dwarf_retrieve_symbol_names(dbg, symbols);
    } catch (...) {
        dwarf_finish(dbg);
        throw;
    }

    dwarf_finish(dbg);
}
