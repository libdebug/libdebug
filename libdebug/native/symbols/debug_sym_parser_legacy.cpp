//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser.h"

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

    // Check if the DIE is a subprogram (function) or a variable
    if (tag == DW_TAG_subprogram || tag == DW_TAG_variable) {
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
                            } else {
                                if (dwarf_formudata(attrs[i], &highpc, &error) == DW_DLV_OK) {
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

            add_symbol_info(symbols, die_name, lowpc, highpc);
        }

        if (die_name) {
            dwarf_dealloc(dbg, die_name, DW_DLA_STRING);
        }
    }
}

void dwarf_retrieve_symbol_names(Dwarf_Debug dbg, SymbolVector &symbols)
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
            throw std::runtime_error("Failed to get the DIE for the current compilation unit");
        }

        if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_OK) {
            while (child_die != NULL) {
                process_die(dbg, child_die, symbols);

                // Get the next DIE (sibling)
                if (dwarf_siblingof(dbg, child_die, &sibling_die, &err) != DW_DLV_OK) {
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
}

void process_dwarf_info(const int fd, SymbolVector &symbols)
{
    Dwarf_Debug dbg;
    Dwarf_Error err;

    // Initialize the DWARF library
    if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        throw std::runtime_error("Failed to initialize the DWARF library");
    }

    dwarf_retrieve_symbol_names(dbg, symbols);

    dwarf_finish(dbg, &err);
}
