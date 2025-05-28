//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "debug_sym_parser.h"

//────────────────────────────  RAII guards  ─────────────────────────────────//
struct FileDescriptorGuard {
    int fd{-1};
    explicit FileDescriptorGuard(int f) noexcept : fd(f) {}
    FileDescriptorGuard             (const FileDescriptorGuard&) = delete;
    FileDescriptorGuard& operator = (const FileDescriptorGuard&) = delete;
    ~FileDescriptorGuard() noexcept { if (fd >= 0) ::close(fd); }
};

struct DwarfHandle {
    Dwarf_Debug dbg{nullptr};
    explicit DwarfHandle(int fd) {
        if (dwarf_init(fd, DW_DLC_READ, nullptr, nullptr, &dbg, nullptr) != DW_DLV_OK)
            throw std::runtime_error("Failed to initialize the DWARF library");
    }
    DwarfHandle             (const DwarfHandle&) = delete;
    DwarfHandle& operator = (const DwarfHandle&) = delete;
    ~DwarfHandle() noexcept { if (dbg) dwarf_finish(dbg, nullptr); }
};

template <typename T, int Kind>
class DwarfAutoFree {
    Dwarf_Debug dbg;
    T          obj;
public:
    DwarfAutoFree(Dwarf_Debug d, T o) : dbg(d), obj(o) {}
    ~DwarfAutoFree(){ if (obj) dwarf_dealloc(dbg, obj, Kind); }
    T get() const noexcept { return obj; }
};


//─────────────────────────── Code Implementation ──────────────────────────//
void parse_highpc(Dwarf_Attribute highpc_attr, Dwarf_Addr &highpc, Dwarf_Addr &lowpc)
{   
    Dwarf_Error error = nullptr;
    Dwarf_Half dw_return_form = 0;

    // Get the form of the highpc attribute
    if (dwarf_whatform(highpc_attr, &dw_return_form, &error) != DW_DLV_OK) {
        throw std::runtime_error("Failed to get the form of the highpc attribute");
    }

    // Check if the highpc is in address form or unit data form
    switch(dw_return_form) {
        #ifdef DW_FORM_addrx
        case DW_FORM_addrx:
        #endif
        case DW_FORM_addr:
            if (dwarf_formaddr(highpc_attr, &highpc, &error) != DW_DLV_OK) {
                throw std::runtime_error("Failed to get the highpc address");
            }
            break;
        case DW_FORM_data4:
        case DW_FORM_data8:
            if (dwarf_formudata(highpc_attr, &highpc, &error) != DW_DLV_OK) {
                throw std::runtime_error("Failed to get the highpc value");
            }
            highpc += lowpc;
            break;
        default:
            throw std::runtime_error("Unsupported form for highpc attribute");
    }
}


void process_subprogram(Dwarf_Debug dbg, Dwarf_Die die, SymbolVector &symbols)
{
    Dwarf_Error error = nullptr;
    char *die_name = nullptr;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Attribute highpc_attr = nullptr;

    if (dwarf_diename(die, &die_name, &error) == DW_DLV_OK) {
        DwarfAutoFree<char*, DW_DLA_STRING> name_guard(dbg, die_name); // RAII

        if (die_name == nullptr || *die_name == '\0') {
            // If the name is empty, we skip this subprogram
            return;
        }

        if (dwarf_lowpc(die, &lowpc, &error) == DW_DLV_OK &&
                dwarf_attr(die, DW_AT_high_pc, &highpc_attr, &error) == DW_DLV_OK) {
                
            DwarfAutoFree<Dwarf_Attribute, DW_DLA_ATTR> attr_guard(dbg, highpc_attr); // RAII
            
            parse_highpc(highpc_attr, highpc, lowpc);

            // Add the symbol to the symbols vector
            add_symbol_info(symbols, die_name, lowpc, highpc);
        }
    }
}

void process_variable(Dwarf_Debug dbg, Dwarf_Die die, SymbolVector &symbols)
{
    Dwarf_Error error = nullptr;
    char *die_name = nullptr;
    Dwarf_Addr lowpc = 0, highpc = 0;
    Dwarf_Attribute loc_attr = nullptr;
    Dwarf_Attribute highpc_attr = nullptr;


    if (dwarf_diename(die, &die_name, &error) == DW_DLV_OK) {
        DwarfAutoFree<char*, DW_DLA_STRING> name_guard(dbg, die_name); // RAII

        if (die_name == nullptr || *die_name == '\0') {
            // If the name is empty, we skip this variable
            return;
        }

        // Some variables, like the global variables, may still have a lowpc and highpc
        // Other variables, like local variables, may not have a lowpc and highpc but an at_location attribute
        if (dwarf_lowpc(die, &lowpc, &error) == DW_DLV_OK &&
                    dwarf_attr(die, DW_AT_high_pc, &highpc_attr, &error) == DW_DLV_OK) {
                
            DwarfAutoFree<Dwarf_Attribute, DW_DLA_ATTR> attr_guard(dbg, highpc_attr); // RAII
            
            parse_highpc(highpc_attr, highpc, lowpc);

            // Add the symbol to the symbols vector
            add_symbol_info(symbols, die_name, lowpc, highpc);
        } else if (dwarf_attr(die, DW_AT_location, &loc_attr, &error) == DW_DLV_OK){
            DwarfAutoFree<Dwarf_Attribute, DW_DLA_ATTR> attr_guard(dbg, loc_attr); // RAII
            add_symbol_info(symbols, die_name, 0, 0);
        }
    }
}


void process_die(Dwarf_Debug dbg, Dwarf_Die die, SymbolVector &symbols)
{
    Dwarf_Error error;
    Dwarf_Half tag;

    if (dwarf_tag(die, &tag, &error) != DW_DLV_OK) {
        throw std::runtime_error("Failed to get the tag of the DIE");
    }

    // Check if the DIE is a subprogram (function) or a variable
    if (tag == DW_TAG_subprogram) {
        process_subprogram(dbg, die, symbols);
    } else if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter) {
        process_variable(dbg, die, symbols);
    } 
}

void traverse_die_and_siblings(Dwarf_Debug dbg, Dwarf_Die die, SymbolVector &symbols) 
{
    // Traverse the tree in a depth-first manner
    Dwarf_Error err = nullptr;

    for (; die != nullptr; ) {
        DwarfAutoFree<Dwarf_Die, DW_DLA_DIE> die_guard(dbg, die); // RAII

        // Process the current DIE before recursing into its children
        process_die(dbg, die, symbols);

        Dwarf_Die child = nullptr;
        
        // Recurse into its children
        switch (dwarf_child(die, &child, &err)) {
            case DW_DLV_OK:
                // Recursive call to traverse the tree in depth-first manner
                traverse_die_and_siblings(dbg, child, symbols);
                break;
            case DW_DLV_ERROR:
                throw std::runtime_error(dwarf_errmsg(err));
            default: ;   // no child
        }

        // Now that we are done with the children (deepest level), we can get all the siblings
        Dwarf_Die next = nullptr;
        int res = dwarf_siblingof(dbg, die, &next, &err);

        if (res == DW_DLV_OK)
            die = next; // move to sibling
        else if (res == DW_DLV_NO_ENTRY)
            break; // end of this sibling chain
        else
            throw std::runtime_error(dwarf_errmsg(err));
    }
}

void dwarf_retrieve_symbol_names(Dwarf_Debug dbg, SymbolVector &symbols)
{
    Dwarf_Error err = nullptr;
    Dwarf_Unsigned cu_header_length = 0, abbrev_offset = 0, next_cu_header = 0;
    Dwarf_Half version_stamp = 0, address_size = 0;
    Dwarf_Die cu_die = nullptr;

    // Loop through all the compilation units. This call will set the inner cursor to the first CU.
    while (dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, 
                                &next_cu_header, &err) == DW_DLV_OK) {

        // Get the DIE for the current compilation unit. 
        // We pass NULL as the first argument to get the first DIE in the current compilation unit.
        if (dwarf_siblingof(dbg, NULL, &cu_die, &err) != DW_DLV_OK) {
            throw std::runtime_error("Failed to get the DIE for the current compilation unit");
        }

        DwarfAutoFree<Dwarf_Die, DW_DLA_DIE> cu_die_guard(dbg, cu_die); // RAII

        // Traverse the DIE and its siblings
        traverse_die_and_siblings(dbg, cu_die, symbols);
    }
}

void process_dwarf_info(const int fd, SymbolVector &symbols)
{
    FileDescriptorGuard fd_guard(fd);  // automatically closes fd
    DwarfHandle         dwarf(fd);     // automatically dwarf_finish()

    dwarf_retrieve_symbol_names(dwarf.dbg, symbols);
}
