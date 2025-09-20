//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "program_header_parsing.h"

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

static const char* p_type_str(Elf64_Word p_type, uint16_t e_machine)
{
    if (e_machine == EM_AARCH64)
    {
        // AArch64 specific PT_* tags
        switch (p_type) {
            case PT_AARCH64_MEMTAG_MTE: return "AARCH64_MEMTAG_MTE";
            default:
                // Fall through to generic handling below
                break;
        }
    }

    switch (p_type)
    {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_SHLIB: return "SHLIB";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
        case PT_NUM: return "NUM";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        case PT_GNU_SFRAME: return "GNU_SFRAME";
        case PT_SUNWBSS: return "SUNWBSS";
        case PT_SUNWSTACK: return "SUNWSTACK";
        case PT_HP_TLS: return "HP_TLS";
        case PT_HP_CORE_NONE: return "HP_CORE_NONE";
        case PT_HP_CORE_VERSION: return "HP_CORE_VERSION";
        case PT_HP_CORE_KERNEL: return "HP_CORE_KERNEL";
        case PT_HP_CORE_COMM: return "HP_CORE_COMM";
        case PT_HP_CORE_PROC: return "HP_CORE_PROC";
        case PT_HP_CORE_LOADABLE: return "HP_CORE_LOADABLE";
        case PT_HP_CORE_STACK: return "HP_CORE_STACK";
        case PT_HP_CORE_SHM: return "HP_CORE_SHM";
        case PT_HP_CORE_MMF: return "HP_CORE_MMF";
        case PT_HP_PARALLEL: return "HP_PARALLEL";
        case PT_HP_FASTBIND: return "HP_FASTBIND";
        case PT_HP_OPT_ANNOT: return "HP_OPT_ANNOT";
        case PT_HP_HSL_ANNOT: return "HP_HSL_ANNOT";
        case PT_HP_STACK: return "HP_STACK";
        default:
            char buf[32];
            std::snprintf(buf, sizeof(buf), "UNKNOWN 0x%" PRIx32, p_type);
            return strdup(buf);
    }
} 

static void pflags_str(Elf64_Word f, std::string& out, uint16_t e_machine)
{
    out.clear();
    if (f & PF_R) out += 'R';
    if (f & PF_W) out += 'W';
    if (f & PF_X) out += 'X';

    if (out.empty()) out = "---";

    // Append other flags in hex
    uint32_t other = (f & ~(PF_R | PF_W | PF_X));
    uint32_t remaining = other;
    
    if (other)
    {
        if (!out.empty()) out += ' ';
        
        if (other & PF_HP_PAGE_SIZE) {
            out += "HP_PAGE_SIZE ";
            remaining &= ~PF_HP_PAGE_SIZE;
        }
        if (other & PF_HP_FAR_SHARED) {
            out += "HP_FAR_SHARED ";
            remaining &= ~PF_HP_FAR_SHARED;
        }
        if (other & PF_HP_NEAR_SHARED) {
            out += "HP_NEAR_SHARED ";
            remaining &= ~PF_HP_NEAR_SHARED;
        }
        if (other & PF_HP_CODE) {
            out += "HP_CODE ";
            remaining &= ~PF_HP_CODE;
        }
        if (other & PF_HP_MODIFY) {
            out += "HP_MODIFY ";
            remaining &= ~PF_HP_MODIFY;
        }
        if (other & PF_HP_LAZYSWAP) {
            out += "HP_LAZYSWAP ";
            remaining &= ~PF_HP_LAZYSWAP;
        }
        if (other & PF_HP_SBP) {
            out += "HP_SBP ";
            remaining &= ~PF_HP_SBP;
        }
    }

    // Remove trailing space if any
    if (!out.empty() && out.back() == ' ') out.pop_back();
}

// If e_phnum == PN_XNUM (0xffff), true phnum is sh_info of section 0.
template <typename EhdrT, typename ShdrT>
static uint16_t resolve_phnum_extended(const uint8_t* data, size_t sz, int swap,
                                       uint64_t e_shoff, uint16_t e_shentsize,
                                       uint16_t e_shnum, uint16_t e_phnum)
{
    if (e_phnum != PN_XNUM)
        return e_phnum;

    if (e_shoff == 0 || e_shnum == 0)
        throw std::runtime_error("PN_XNUM but no section headers to resolve phnum");

    if (e_shentsize != sizeof(ShdrT))
        throw std::runtime_error("Unexpected e_shentsize while resolving PN_XNUM");

    if (!in_bounds((size_t)e_shoff, (size_t)e_shentsize, sz))
        throw std::runtime_error("Section header[0] out of bounds while resolving PN_XNUM");

    const ShdrT* sh0 = (const ShdrT*)(data + (size_t)e_shoff);

    uint32_t sh0_info = std::is_same<ShdrT, Elf64_Shdr>::value
                        ? maybe32((uint32_t)((const Elf64_Shdr*)sh0)->sh_info, swap)
                        : maybe32(((const Elf32_Shdr*)sh0)->sh_info, swap);

    if (sh0_info > 0xFFFFu)
        throw std::runtime_error("Extended phnum too large");

    return (uint16_t)sh0_info;
}

static void parse_program_headers_64(const uint8_t* data, size_t sz, int swap, std::vector<ProgramHeaderInfo>& out){
    if (!in_bounds(0, sizeof(Elf64_Ehdr), sz))
        throw std::runtime_error("Truncated ELF header (64)");

    const Elf64_Ehdr* eh = (const Elf64_Ehdr*)data;

    uint64_t e_phoff     = maybe64(eh->e_phoff, swap);
    uint16_t e_phentsize = maybe16(eh->e_phentsize, swap);
    uint16_t e_phnum     = maybe16(eh->e_phnum, swap);
    uint64_t e_shoff     = maybe64(eh->e_shoff, swap);
    uint16_t e_shentsize = maybe16(eh->e_shentsize, swap);
    uint16_t e_shnum     = maybe16(eh->e_shnum, swap);

    if (e_phoff == 0 || e_phnum == 0)
        throw std::runtime_error("This ELF has no program header table");

    if (e_phentsize != sizeof(Elf64_Phdr))
        throw std::runtime_error("Unexpected e_phentsize for 64-bit ELF");

    // Handle PN_XNUM
    e_phnum = resolve_phnum_extended<Elf64_Ehdr, Elf64_Shdr>(data, sz, swap, e_shoff, e_shentsize, e_shnum, e_phnum);

    size_t phdrs_size = (size_t)e_phentsize * (size_t)e_phnum;
    if (!in_bounds((size_t)e_phoff, phdrs_size, sz))
        throw std::runtime_error("Program headers out of bounds (64)");

    const uint8_t* p = data + (size_t)e_phoff;
    out.reserve(out.size() + e_phnum);

    uint16_t e_machine = maybe16(eh->e_machine, swap);

    for (uint16_t i = 0; i < e_phnum; ++i, p += e_phentsize) {
        const Elf64_Phdr* ph = (const Elf64_Phdr*)p;

        uint32_t p_type   = maybe32(ph->p_type,   swap);
        uint32_t p_flags  = maybe32(ph->p_flags,  swap);
        uint64_t p_offset = maybe64(ph->p_offset, swap);
        uint64_t p_vaddr  = maybe64(ph->p_vaddr,  swap);
        uint64_t p_paddr  = maybe64(ph->p_paddr,  swap);
        uint64_t p_filesz = maybe64(ph->p_filesz, swap);
        uint64_t p_memsz  = maybe64(ph->p_memsz,  swap);
        uint64_t p_align  = maybe64(ph->p_align,  swap);

        if (p_filesz && !in_bounds((size_t)p_offset, (size_t)p_filesz, sz)) {
            // PT_NOTE and some others can have odd sizes; still must be in file.
            throw std::runtime_error("Program header payload out of bounds (64)");
        }

        if (p_align && !is_p2(p_align)) {
            std::fprintf(stderr, "Warn: phdr %u has non power-of-two p_align=%" PRIu64 "\n", (unsigned)i, p_align);
        }

        ProgramHeaderInfo info;
        info.type   =  (char*)p_type_str(p_type, e_machine);
        info.offset = (Elf64_Off)p_offset;
        info.vaddr  = (Elf64_Addr)p_vaddr;
        info.paddr  = (Elf64_Addr)p_paddr;
        info.filesz = (Elf64_Xword)p_filesz;
        info.memsz  = (Elf64_Xword)p_memsz;
        info.align  = (Elf64_Xword)p_align;
        pflags_str(p_flags, info.flags, e_machine);

        out.push_back(std::move(info));
    }
}

static void parse_program_headers_32(const uint8_t* data, size_t sz, int swap, std::vector<ProgramHeaderInfo>& out){
    if (!in_bounds(0, sizeof(Elf32_Ehdr), sz))
        throw std::runtime_error("Truncated ELF header (32)");

    const Elf32_Ehdr* eh = (const Elf32_Ehdr*)data;

    uint32_t e_phoff     = maybe32(eh->e_phoff, swap);
    uint16_t e_phentsize = maybe16(eh->e_phentsize, swap);
    uint16_t e_phnum     = maybe16(eh->e_phnum, swap);
    uint32_t e_shoff     = maybe32(eh->e_shoff, swap);
    uint16_t e_shentsize = maybe16(eh->e_shentsize, swap);
    uint16_t e_shnum     = maybe16(eh->e_shnum, swap);

    if (e_phoff == 0 || e_phnum == 0)
        throw std::runtime_error("This ELF has no program header table");

    if (e_phentsize != sizeof(Elf32_Phdr))
        throw std::runtime_error("Unexpected e_phentsize for 32-bit ELF");

    // Handle PN_XNUM
    e_phnum = resolve_phnum_extended<Elf32_Ehdr, Elf32_Shdr>(data, sz, swap, e_shoff, e_shentsize, e_shnum, e_phnum);

    size_t phdrs_size = (size_t)e_phentsize * (size_t)e_phnum;
    if (!in_bounds((size_t)e_phoff, phdrs_size, sz))
        throw std::runtime_error("Program headers out of bounds (32)");

    const uint8_t* p = data + (size_t)e_phoff;
    out.reserve(out.size() + e_phnum);

    uint16_t e_machine = maybe16(eh->e_machine, swap);

    for (uint16_t i = 0; i < e_phnum; ++i, p += e_phentsize) {
        const Elf32_Phdr* ph = (const Elf32_Phdr*)p;

        uint32_t p_type   = maybe32(ph->p_type,   swap);
        uint32_t p_offset = maybe32(ph->p_offset, swap);
        uint32_t p_vaddr  = maybe32(ph->p_vaddr,  swap);
        uint32_t p_paddr  = maybe32(ph->p_paddr,  swap);
        uint32_t p_filesz = maybe32(ph->p_filesz, swap);
        uint32_t p_memsz  = maybe32(ph->p_memsz,  swap);
        uint32_t p_flags  = maybe32(ph->p_flags,  swap);
        uint32_t p_align  = maybe32(ph->p_align,  swap);

        if (p_filesz && !in_bounds((size_t)p_offset, (size_t)p_filesz, sz)) {
            throw std::runtime_error("Program header payload out of bounds (32)");
        }

        if (p_align && !is_p2(p_align)) {
            std::fprintf(stderr, "Warn: phdr %u has non power-of-two p_align=%" PRIu64 "\n", (unsigned)i, (uint64_t)p_align);
        }

        ProgramHeaderInfo info;
        info.type   =  (char*)p_type_str(p_type, e_machine);
        info.offset = (Elf64_Off)p_offset;
        info.vaddr  = (Elf64_Addr)p_vaddr;
        info.paddr  = (Elf64_Addr)p_paddr;
        info.filesz = (Elf64_Xword)p_filesz;
        info.memsz  = (Elf64_Xword)p_memsz;
        info.align  = (Elf64_Xword)p_align;
        pflags_str(p_flags, info.flags, e_machine);

        out.push_back(std::move(info));
    }
}

static void internal_parse_program_headers(const uint8_t* data, size_t sz, std::vector<ProgramHeaderInfo>& out){
    if (sz < EI_NIDENT) throw std::runtime_error("File too small");
    if (!(data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F'))
        throw std::runtime_error("Not an ELF file");

    int file_le;
    switch (data[EI_DATA]) {
        case ELFDATA2LSB: file_le = 1; break;
        case ELFDATA2MSB: file_le = 0; break;
        default: throw std::runtime_error("Unknown ELF data encoding");
    }
    int swap = (file_le != host_is_le());

    int cls = data[EI_CLASS];
    if (cls == ELFCLASS64) {
        parse_program_headers_64(data, sz, swap, out);
    } else if (cls == ELFCLASS32) {
        parse_program_headers_32(data, sz, swap, out);
    } else {
        throw std::runtime_error("Unsupported ELF class");
    }
}

// -------------------- Public API --------------------

ProgramHeaderTable ProgramHeaderTable::parse_file(const char* filename){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    ProgramHeaderTable tbl;
    internal_parse_program_headers(buf.data(), buf.size(), tbl.headers);
    return tbl;
}

// -------------------- Nanobind module --------------------

namespace nb = nanobind;

NB_MODULE(libdebug_program_header_parser, m) {
    nb::class_<ProgramHeaderInfo>(m, "ProgramHeader", "ELF program header (segment)")
        .def_ro("type",   &ProgramHeaderInfo::type,   "Segment type (p_type)")
        .def_ro("offset", &ProgramHeaderInfo::offset, "Offset in file (p_offset)")
        .def_ro("vaddr",  &ProgramHeaderInfo::vaddr,  "Virtual address in memory (p_vaddr)")
        .def_ro("paddr",  &ProgramHeaderInfo::paddr,  "Physical address (p_paddr)")
        .def_ro("filesz", &ProgramHeaderInfo::filesz, "File size (p_filesz)")
        .def_ro("memsz",  &ProgramHeaderInfo::memsz,  "Memory size (p_memsz)")
        .def_ro("flags",  &ProgramHeaderInfo::flags,  "Flags parsed string (R/W/X)")
        .def_ro("align",  &ProgramHeaderInfo::align,  "Alignment (p_align)");

    nb::class_<ProgramHeaderTable>(m, "ProgramHeaderTable", "Container for ELF program headers")
        .def_prop_ro(
            "headers",
            [](const ProgramHeaderTable& t) { return t.headers; },
            "List of program headers in file order")
        .def_static("from_file", &ProgramHeaderTable::parse_file,
                    nb::arg("elf_file_path"),
                    "Parse program headers from an ELF file and return a ProgramHeaderTable");
}
