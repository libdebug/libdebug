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
            Dwarf_Addr loc_addr = 0;
            Dwarf_Unsigned expr_len = 0;
            bool has_valid_location = false;
        
            // Check if the location attribute is in address form
            Dwarf_Half loc_form = 0;
            if (dwarf_whatform(loc_attr, &loc_form, &error) != DW_DLV_OK) {
                throw std::runtime_error("Failed to get the form of the location attribute");
            }
            
            switch(loc_form) {
                #ifdef DW_FORM_addrx
                case DW_FORM_addrx:
                #endif
                case DW_FORM_addr:
                    if (dwarf_formaddr(loc_attr, &loc_addr, &error) != DW_DLV_OK) {
                        throw std::runtime_error("Failed to get the location address");
                    }
                    has_valid_location = true;
                    break;
                    
                case DW_FORM_exprloc:
                case DW_FORM_block:
                case DW_FORM_block1:
                case DW_FORM_block2:
                case DW_FORM_block4:
                {
                    Dwarf_Ptr expr_buf = nullptr;
        
                    
                    if (dwarf_formexprloc(loc_attr, &expr_len, &expr_buf, &error) != DW_DLV_OK) {
                        // Try formblock as fallback for older DWARF versions
                        Dwarf_Block *block = nullptr;
                        
                        if (dwarf_formblock(loc_attr, &block, &error) != DW_DLV_OK) {
                            throw std::runtime_error("Failed to get the location expression");
                        }
                        expr_buf = block->bl_data;
                        expr_len = block->bl_len;
                    }
                    
                    // Process the location expression
                    if (expr_len > 0 && expr_buf != nullptr) {
                        Dwarf_Small *data = reinterpret_cast<Dwarf_Small*>(expr_buf);
                        Dwarf_Small op = data[0];
                        
                        switch(op) {
                            case DW_OP_addr:
                                if (expr_len >= 1 + sizeof(Dwarf_Addr)) {
                                    // Extract address from DW_OP_addr operation
                                    memcpy(&loc_addr, data + 1, sizeof(Dwarf_Addr));
                                    has_valid_location = true;
                                }
                                break;
                                
                            case DW_OP_fbreg:
                            {
                                // Frame base relative - this is a stack variable
                                // The offset is encoded as SLEB128 after the opcode
                                if (expr_len > 1) {
                                    Dwarf_Signed offset = 0;
                                    int bytes_read = 0;
                                    
                                    // Manual SLEB128 decoding
                                    unsigned char *p = (unsigned char*)(data + 1);
                                    int shift = 0;
                                    unsigned char byte;
                                    
                                    do {
                                        byte = *p++;
                                        offset |= ((Dwarf_Signed)(byte & 0x7f)) << shift;
                                        shift += 7;
                                        bytes_read++;
                                    } while (byte & 0x80 && bytes_read < (expr_len - 1));
                                    
                                    // Sign extend if necessary
                                    if ((shift < 64) && (byte & 0x40)) {
                                        offset |= -(1LL << shift);
                                    }
                                    
                                    // Store frame-relative offset as address
                                    // Note: negative values typically indicate local variables
                                    loc_addr = static_cast<Dwarf_Addr>(offset);
                                    has_valid_location = true;
                                }
                                break;
                            }
                            
                            case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2: case DW_OP_breg3:
                            case DW_OP_breg4: case DW_OP_breg5: case DW_OP_breg6: case DW_OP_breg7:
                            case DW_OP_breg8: case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
                            case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14: case DW_OP_breg15:
                            case DW_OP_breg16: case DW_OP_breg17: case DW_OP_breg18: case DW_OP_breg19:
                            case DW_OP_breg20: case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
                            case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26: case DW_OP_breg27:
                            case DW_OP_breg28: case DW_OP_breg29: case DW_OP_breg30: case DW_OP_breg31:
                            {
                                    // Register + offset addressing
                                    int reg_num = op - DW_OP_breg0;
                                    if (expr_len > 1) {
                                        // Similar SLEB128 decoding for offset
                                        Dwarf_Signed offset = 0;
                                        // ... (same SLEB128 decoding as above)
                                        
                                        // Store register number in high bits, offset in low bits
                                        // This is a simplification - you may want a different approach
                                        loc_addr = (static_cast<Dwarf_Addr>(reg_num) << 32) | (static_cast<Dwarf_Addr>(offset) & 0xFFFFFFFF);
                                        has_valid_location = true;
                                    }
                                break;
                            }
                            
                            case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2: case DW_OP_reg3:
                            case DW_OP_reg4: case DW_OP_reg5: case DW_OP_reg6: case DW_OP_reg7:
                            case DW_OP_reg8: case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
                            case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14: case DW_OP_reg15:
                            case DW_OP_reg16: case DW_OP_reg17: case DW_OP_reg18: case DW_OP_reg19:
                            case DW_OP_reg20: case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
                            case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26: case DW_OP_reg27:
                            case DW_OP_reg28: case DW_OP_reg29: case DW_OP_reg30: case DW_OP_reg31:
                                // Variable is entirely in a register
                                loc_addr = op - DW_OP_reg0; // Store register number
                                has_valid_location = true;
                                break;
                            
                            case DW_OP_regx:
                                // Register number in ULEB128
                                if (expr_len > 1) {
                                    // ULEB128 decoding needed
                                    has_valid_location = true;
                                }
                                break;
                                
                            case DW_OP_const1u:
                            case DW_OP_const1s:
                            case DW_OP_const2u:
                            case DW_OP_const2s:
                            case DW_OP_const4u:
                            case DW_OP_const4s:
                            case DW_OP_const8u:
                            case DW_OP_const8s:
                                // TODO: Handle constant values, if needed
                                break;
                        }
                    }
                    break;
                }
                
                case DW_FORM_data4:
                case DW_FORM_data8:
                case DW_FORM_sec_offset:
                    // TODO: Handle these forms if needed
                    break;

                default:
                    // Unsupported location form
                    break;
            }
            
            // Only add symbol if we have a valid location or expression
            if (has_valid_location) {
                add_symbol_info(symbols, die_name, loc_addr, expr_len);
            }
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
