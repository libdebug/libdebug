//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "elf_api.h"

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

static void sh_flags_str(uint64_t f, std::string& out, uint16_t e_machine = 0) {
    out.clear();
    if (f & SHF_WRITE)      out += 'W';
    if (f & SHF_ALLOC)      out += 'A';
    if (f & SHF_EXECINSTR)  out += 'X';
    if (f & SHF_MERGE)      out += 'M';
    if (f & SHF_STRINGS)    out += 'S';
    if (f & SHF_INFO_LINK)  out += 'I';
    if (f & SHF_LINK_ORDER) out += 'L';
    if (f & SHF_OS_NONCONFORMING) out += 'O';
    if (f & SHF_GROUP)      out += 'G';
    if (f & SHF_TLS)        out += 'T';
    if (f & SHF_COMPRESSED) out += 'C';
    if (f & SHF_EXCLUDE)    out += 'E';
    if (f & SHF_GNU_RETAIN) out += " RETAIN";
    if (f & SHF_GNU_MBIND)  out += " MBIND";
    
    uint64_t remaining = f & ~(SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_MERGE | SHF_STRINGS |
                            SHF_INFO_LINK | SHF_LINK_ORDER | SHF_OS_NONCONFORMING |
                            SHF_GROUP | SHF_TLS | SHF_COMPRESSED | SHF_EXCLUDE |
                            SHF_GNU_RETAIN | SHF_GNU_MBIND);
    
    if (e_machine == EM_X86_64)
    {
        // x86_64 specific flags
        if (f & SHF_X86_64_LARGE)
        {
            remaining &= ~SHF_X86_64_LARGE;
            out += " LARGE";
        }
        
    }
    else if (e_machine == EM_AARCH64)
    {
        if (f & SHF_ENTRYSECT)
        {
            remaining &= ~SHF_ENTRYSECT;
            out += " ENTRYSECT";
        }
        if (f & SHF_COMDEF)
        {
            remaining &= ~SHF_COMDEF;
            out += " COMDEF";
        }
    }

    if (remaining != 0) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), " UNKNOWN_FLAGS_0x%" PRIx64, remaining);
        out += buf;
    }
}

static const char* sh_type_str(uint32_t sh_type, uint16_t e_machine = 0) {
    // Let's first parse potential architecture-specific types
    // These are externally defined, no need for #ifdef
    if (e_machine == EM_386 || e_machine == EM_X86_64)
    {
        switch (sh_type) {
            case SHT_X86_64_UNWIND: return "X86_64_UNWIND";
            default:
                // Fall through to generic handling below
                break;
        }
    }
    else if (e_machine == EM_AARCH64)
    {
        switch (sh_type) {
            case SHT_AARCH64_ATTRIBUTES: return "AARCH64_ATTRIBUTES";
            case SHT_AARCH64_AUTH_RELR:  return "AARCH64_AUTH_RELR";
            case SHT_AARCH64_MEMTAG_GLOBALS_STATIC:  return "AARCH64_MEMTAG_GLOBALS_STATIC";
            case SHT_AARCH64_MEMTAG_GLOBALS_DYNAMIC: return "AARCH64_MEMTAG_GLOBALS_DYNAMIC";
            default:
                // Fall through to generic handling below
                break;
        }
    }

    switch (sh_type) {
        case SHT_NULL:          return "NULL";
        case SHT_PROGBITS:      return "PROGBITS";
        case SHT_SYMTAB:        return "SYMTAB";
        case SHT_STRTAB:        return "STRTAB";
        case SHT_RELA:          return "RELA";
        case SHT_HASH:          return "HASH";
        case SHT_DYNAMIC:       return "DYNAMIC";
        case SHT_NOTE:          return "NOTE";
        case SHT_NOBITS:        return "NOBITS";
        case SHT_REL:           return "REL";
        case SHT_SHLIB:         return "SHLIB";
        case SHT_DYNSYM:        return "DYNSYM";
        case SHT_INIT_ARRAY:    return "INIT_ARRAY";
        case SHT_FINI_ARRAY:    return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP:         return "GROUP";
        case SHT_SYMTAB_SHNDX:  return "SYMTAB_SHNDX";
        case SHT_RELR:          return "RELR";
        // -------------------- Android extensions -------------------- //
        case SHT_ANDROID_REL:  return "ANDROID_REL";
        case SHT_ANDROID_RELA: return "ANDROID_RELA";
        case SHT_ANDROID_RELR: return "ANDROID_RELR";
        // -------------------- GNU extensions -------------------- //
        case SHT_GNU_INCREMENTAL_INPUTS: return "GNU_INCREMENTAL_INPUTS";
        case SHT_GNU_ATTRIBUTES: return "GNU_ATTRIBUTES";
        case SHT_GNU_HASH:      return "GNU_HASH";
        case SHT_GNU_LIBLIST:   return "GNU_LIBLIST";
        case SHT_CHECKSUM:      return "CHECKSUM";
        case SHT_GNU_verdef:    return "GNU_VERDEF";
        case SHT_GNU_verneed:   return "GNU_VERNEED";
        case SHT_GNU_versym:    return "GNU_VERSYM";
        case SHT_GNU_SFRAME:    return "GNU_SFRAME";
        case SHT_GNU_OBJECT_ONLY: return "GNU_OBJECT_ONLY";
        // -------------------- SUNW extensions -------------------- //
        case SHT_SUNW_move:     return "SUNW_MOVE";
        case SHT_SUNW_COMDAT:   return "SUNW_COMDAT";
        case SHT_SUNW_syminfo:  return "SUNW_SYMINFO";
        // -------------------- LLVM extensions -------------------- //
        case SHT_LLVM_ODRTAB:              return "LLVM_ODRTAB";
        case SHT_LLVM_LINKER_OPTIONS:      return "LLVM_LINKER_OPTIONS";
        case SHT_LLVM_ADDRSIG:             return "LLVM_ADDRSIG";
        case SHT_LLVM_DEPENDENT_LIBRARIES: return "LLVM_DEPENDENT_LIBRARIES";
        case SHT_LLVM_SYMPART:             return "LLVM_SYMPART";
        case SHT_LLVM_PART_EHDR:           return "LLVM_PART_EHDR";
        case SHT_LLVM_PART_PHDR:           return "LLVM_PART_PHDR";
        case SHT_LLVM_BB_ADDR_MAP_V0:      return "LLVM_BB_ADDR_MAP_V0";
        case SHT_LLVM_CALL_GRAPH_PROFILE:  return "LLVM_CALL_GRAPH_PROFILE";
        case SHT_LLVM_BB_ADDR_MAP:         return "LLVM_BB_ADDR_MAP";
        case SHT_LLVM_OFFLOADING:          return "LLVM_OFFLOADING";
        case SHT_LLVM_LTO:                 return "LLVM_LTO";
        default: {
            static thread_local char buf[32];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_0x%" PRIx32, sh_type);
            return buf;
        }
    }
}

static void parse_sections_64(const uint8_t *data, size_t sz, int swap, std::vector<SectionInfo>& out){
    if (!in_bounds(0, sizeof(Elf64_Ehdr), sz))
        throw std::runtime_error("Truncated ELF header");
    const Elf64_Ehdr *eh = (const Elf64_Ehdr*)data;

    uint16_t e_shentsize = maybe16(eh->e_shentsize, swap);
    uint16_t e_shnum     = maybe16(eh->e_shnum, swap);
    uint16_t e_shstrndx  = maybe16(eh->e_shstrndx, swap);
    uint64_t e_shoff     = maybe64(eh->e_shoff, swap);

    if (e_shoff == 0 || e_shnum == 0)
        throw std::runtime_error("This ELF has no section header table (stripped?).");

    // Correctness: e_shentsize must match Elf64_Shdr
    if (e_shentsize != sizeof(Elf64_Shdr))
        throw std::runtime_error("Unexpected e_shentsize for 64-bit ELF");

    // Section 0 may carry extended counts
    if (e_shnum == 0 || e_shstrndx == SHN_XINDEX) {
        if (!in_bounds((size_t)e_shoff, (size_t)e_shentsize, sz))
            throw std::runtime_error("Bad e_shoff/e_shentsize");
        const Elf64_Shdr *sh0 = (const Elf64_Shdr*)(data + e_shoff);
        uint64_t sh0_size = maybe64(sh0->sh_size, swap);
        uint32_t sh0_link = maybe32(sh0->sh_link, swap);
        if (e_shnum == 0) {
            if (sh0_size > 0xFFFFFFFFull) throw std::runtime_error("Extended e_shnum too large");
            e_shnum = (uint16_t)sh0_size;
        }
        if (e_shstrndx == SHN_XINDEX) {
            if (sh0_link > 0xFFFFu) throw std::runtime_error("Extended e_shstrndx too large");
            e_shstrndx = (uint16_t)sh0_link;
        }
    }

    size_t shdrs_size = (size_t)e_shentsize * (size_t)e_shnum;
    if (!in_bounds((size_t)e_shoff, shdrs_size, sz))
        throw std::runtime_error("Section headers out of bounds");

    const Elf64_Shdr *shdrs = (const Elf64_Shdr*)(data + e_shoff);

    // Load section header string table
    if (!(e_shstrndx < e_shnum)) throw std::runtime_error("e_shstrndx out of range");
    const Elf64_Shdr *shstr = (const Elf64_Shdr*)((const uint8_t*)shdrs + (size_t)e_shentsize * (size_t)e_shstrndx);
    uint64_t shstr_off = maybe64(shstr->sh_offset, swap);
    uint64_t shstr_size = maybe64(shstr->sh_size, swap);
    if (!in_bounds((size_t)shstr_off, (size_t)shstr_size, sz))
        throw std::runtime_error(".shstrtab out of bounds");
    const char *strtab = (const char*)(data + (size_t)shstr_off);
    size_t strtab_sz = (size_t)shstr_size;

    out.reserve(out.size() + e_shnum);

    for (uint16_t i = 0; i < e_shnum; ++i){
        const Elf64_Shdr *sh = (const Elf64_Shdr*)((const uint8_t*)shdrs + (size_t)e_shentsize * (size_t)i);
        uint32_t sh_name     = maybe32(sh->sh_name, swap);
        uint32_t sh_type     = maybe32(sh->sh_type, swap);
        uint64_t sh_flags    = maybe64(sh->sh_flags, swap);
        uint64_t sh_addr     = maybe64(sh->sh_addr, swap);
        uint64_t sh_offset   = maybe64(sh->sh_offset, swap);
        uint64_t sh_size     = maybe64(sh->sh_size, swap);
        uint64_t sh_addralign= maybe64(sh->sh_addralign, swap);

        const char *name_c = "(bad-name)";
        if (sh_name < strtab_sz){
            const char *cand = strtab + sh_name;
            size_t remain = strtab_sz - sh_name;
            size_t k = 0;
            for (; k < remain && cand[k] != '\0'; ++k) {}
            if (k < remain) name_c = cand;
        }

        if (!(sh_addralign != 0 || sh_type == SHT_NOBITS || sh_size == 0))
            throw std::runtime_error("Zero sh_addralign for non-empty/non-NOBITS section");

        if (sh_type != SHT_NOBITS) {
            if (!in_bounds((size_t)sh_offset, (size_t)sh_size, sz))
                throw std::runtime_error("Section data out of bounds");
        }

        SectionInfo s;
        s.index = i;
        s.type.assign(sh_type_str(sh_type, maybe16(eh->e_machine, swap)));
        sh_flags_str(sh_flags, s.flags, eh->e_machine); // convert to string
        s.addr = sh_addr;
        s.offset = sh_offset;
        s.size = sh_size;
        s.addralign = sh_addralign;
        s.name = name_c;
        out.push_back(std::move(s));
    }
}

static void parse_sections_32(const uint8_t *data, size_t sz, int swap, std::vector<SectionInfo>& out){
    if (!in_bounds(0, sizeof(Elf32_Ehdr), sz)) throw std::runtime_error("Truncated ELF header");
    const Elf32_Ehdr *eh = (const Elf32_Ehdr*)data;

    uint16_t e_shentsize = maybe16(eh->e_shentsize, swap);
    uint16_t e_shnum     = maybe16(eh->e_shnum, swap);
    uint16_t e_shstrndx  = maybe16(eh->e_shstrndx, swap);
    uint32_t e_shoff     = maybe32(eh->e_shoff, swap);

    if (e_shentsize != sizeof(Elf32_Shdr))
        throw std::runtime_error("Unexpected e_shentsize for 32-bit ELF");

    // Extended numbering via section 0
    if ((e_shnum == 0 || e_shstrndx == SHN_XINDEX) && e_shoff != 0) {
        if (!in_bounds((size_t)e_shoff, (size_t)e_shentsize, sz))
            throw std::runtime_error("Bad e_shoff/e_shentsize");
        const Elf32_Shdr *sh0 = (const Elf32_Shdr*)(data + e_shoff);
        uint32_t sh0_size = maybe32(sh0->sh_size, swap);
        uint32_t sh0_link = maybe32(sh0->sh_link, swap);
        if (e_shnum == 0) {
            if (sh0_size > 0xFFFFu) throw std::runtime_error("Extended e_shnum too large");
            e_shnum = (uint16_t)sh0_size;
        }
        if (e_shstrndx == SHN_XINDEX) {
            if (sh0_link > 0xFFFFu) throw std::runtime_error("Extended e_shstrndx too large");
            e_shstrndx = (uint16_t)sh0_link;
        }
    }

    size_t shdrs_size = (size_t)e_shentsize * (size_t)e_shnum;
    if (!in_bounds((size_t)e_shoff, shdrs_size, sz))
        throw std::runtime_error("Section headers out of bounds");

    const Elf32_Shdr *shdrs = (const Elf32_Shdr*)(data + e_shoff);

    // Load section header string table
    if (!(e_shstrndx < e_shnum)) throw std::runtime_error("e_shstrndx out of range");
    const Elf32_Shdr *shstr = (const Elf32_Shdr*)((const uint8_t*)shdrs + (size_t)e_shentsize * (size_t)e_shstrndx);
    uint32_t shstr_off = maybe32(shstr->sh_offset, swap);
    uint32_t shstr_size = maybe32(shstr->sh_size, swap);
    if (!in_bounds((size_t)shstr_off, (size_t)shstr_size, sz))
        throw std::runtime_error(".shstrtab out of bounds");
    const char *strtab = (const char*)(data + (size_t)shstr_off);
    size_t strtab_sz = (size_t)shstr_size;

    out.reserve(out.size() + e_shnum);

    for (uint16_t i = 0; i < e_shnum; ++i){
        const Elf32_Shdr *sh = (const Elf32_Shdr*)((const uint8_t*)shdrs + (size_t)e_shentsize * (size_t)i);
        uint32_t sh_name     = maybe32(sh->sh_name, swap);
        uint32_t sh_type     = maybe32(sh->sh_type, swap);
        uint32_t sh_flags    = maybe32(sh->sh_flags, swap);
        uint32_t sh_addr     = maybe32(sh->sh_addr, swap);
        uint32_t sh_offset   = maybe32(sh->sh_offset, swap);
        uint32_t sh_size     = maybe32(sh->sh_size, swap);
        uint32_t sh_addralign= maybe32(sh->sh_addralign, swap);

        const char *name_c = "(bad-name)";
        if (sh_name < strtab_sz){
            const char *cand = strtab + sh_name;
            size_t remain = strtab_sz - sh_name, k = 0;
            for (; k < remain && cand[k] != '\0'; ++k) {}
            if (k < remain) name_c = cand;
        }

        if (!(sh_addralign != 0 || sh_type == SHT_NOBITS || sh_size == 0))
            throw std::runtime_error("Zero sh_addralign for non-empty/non-NOBITS section");

        if (sh_type != SHT_NOBITS) {
            if (!in_bounds((size_t)sh_offset, (size_t)sh_size, sz))
                throw std::runtime_error("Section data out of bounds");
        }

        SectionInfo s;
        s.index = i;
        s.type.assign(sh_type_str(sh_type, maybe16(eh->e_machine, swap)));
        sh_flags_str(sh_flags, s.flags, eh->e_machine); // convert to string
        s.addr = sh_addr;
        s.offset = sh_offset;
        s.size = sh_size;
        s.addralign = sh_addralign;
        s.name = name_c;
        out.push_back(std::move(s));
    }
}

static void internal_parse_elf_sections(const uint8_t *data, size_t sz, std::vector<SectionInfo>& out){
    if (sz < EI_NIDENT) throw std::runtime_error("File too small");
    if (!(data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F')) throw std::runtime_error("Not an ELF file");

    int file_le;
    switch (data[EI_DATA]) {
        case ELFDATA2LSB: file_le = 1; break;
        case ELFDATA2MSB: file_le = 0; break;
        default: throw std::runtime_error("Unknown ELF data encoding");
    }
    int swap = (file_le != host_is_le());

    int cls = data[EI_CLASS];
    if (cls == ELFCLASS64) {
        if (!in_bounds(0, sizeof(Elf64_Ehdr), sz)) throw std::runtime_error("Truncated ELF header (64)");
        // Touch some fields to validate endianness (not used further)
        const Elf64_Ehdr *eh = (const Elf64_Ehdr*)data;
        (void)maybe16(eh->e_type, swap);
        (void)maybe16(eh->e_machine, swap);
        (void)maybe32(eh->e_version, swap);

        parse_sections_64(data, sz, swap, out);
    } else if (cls == ELFCLASS32) {
        if (!in_bounds(0, sizeof(Elf32_Ehdr), sz)) throw std::runtime_error("Truncated ELF header (32)");
        const Elf32_Ehdr *eh = (const Elf32_Ehdr*)data;
        (void)maybe16(eh->e_type, swap);
        (void)maybe16(eh->e_machine, swap);
        (void)maybe32(eh->e_version, swap);

        parse_sections_32(data, sz, swap, out);
    } else {
        throw std::runtime_error("Unsupported ELF class");
    }
}

// -------------------- Dynamic section parsing --------------------

static const char* dt_tag_name(int64_t tag, uint16_t e_machine) {
    // Architecture-specific DT_* tags
    // These are externally defined, no need for #ifdef
    if (e_machine == EM_X86_64)
    {
        switch (tag) {
            case DT_X86_64_PLT: return "X86_64_PLT";
            case DT_X86_64_PLTSZ: return "X86_64_PLTSZ";
            case DT_X86_64_PLTENT: return "X86_64_PLTENT";
            default:
                // Fall through to generic handling below
                break;
        }
    }
    else if (e_machine == EM_AARCH64) {
        switch (tag) {
            case DT_AARCH64_BTI_PLT: return "AARCH64_BTI_PLT";
            case DT_AARCH64_PAC_PLT: return "AARCH64_PAC_PLT";
            case DT_AARCH64_VARIANT_PCS: return "AARCH64_VARIANT_PCS";
            case DT_AARCH64_MEMTAG_MODE: return "AARCH64_MEMTAG_MODE";
            case DT_AARCH64_MEMTAG_STACK: return "AARCH64_MEMTAG_STACK";
            default:
                // Fall through to generic handling below
                break;
        }
    }

    switch (tag) {
        case DT_NULL:            return "NULL";
        case DT_NEEDED:          return "NEEDED";
        case DT_PLTRELSZ:        return "PLTRELSZ";
        case DT_PLTGOT:          return "PLTGOT";
        case DT_HASH:            return "HASH";
        case DT_STRTAB:          return "STRTAB";
        case DT_SYMTAB:          return "SYMTAB";
        case DT_RELASZ:          return "RELASZ";
        case DT_RELAENT:         return "RELAENT";
        case DT_STRSZ:           return "STRSZ";
        case DT_SYMENT:          return "SYMENT";
        case DT_INIT:            return "INIT";
        case DT_FINI:            return "FINI";
        case DT_SONAME:          return "SONAME";
        case DT_RPATH:           return "RPATH";
        case DT_SYMBOLIC:        return "SYMBOLIC";
        case DT_RELSZ:           return "RELSZ";
        case DT_RELENT:          return "RELENT";
        case DT_PLTREL:          return "PLTREL";
        case DT_DEBUG:           return "DEBUG";
        case DT_TEXTREL:         return "TEXTREL";
        case DT_JMPREL:          return "JMPREL";
        case DT_BIND_NOW:        return "BIND_NOW";
        case DT_INIT_ARRAY:      return "INIT_ARRAY";
        case DT_FINI_ARRAY:      return "FINI_ARRAY";
        case DT_INIT_ARRAYSZ:    return "INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ:    return "FINI_ARRAYSZ";
        case DT_RUNPATH:         return "RUNPATH";
        case DT_FLAGS:           return "FLAGS";
        case DT_PREINIT_ARRAY:   return "PREINIT_ARRAY";
        case DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ";
        case DT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";
        case DT_RELRSZ: return "RELRSZ";
        case DT_RELR: return "RELR";
        case DT_RELRENT: return "RELRENT";
        case DT_GNU_FLAGS_1: return "GNU_FLAGS_1";
        case DT_GNU_PRELINKED: return "GNU_PRELINKED";
        case DT_GNU_CONFLICTSZ: return "GNU_CONFLICTSZ";
        case DT_GNU_LIBLISTSZ: return "GNU_LIBLISTSZ";
        case DT_CHECKSUM: return "CHECKSUM";
        case DT_PLTPADSZ: return "PLTPADSZ";
        case DT_MOVEENT: return "MOVEENT";
        case DT_MOVESZ: return "MOVESZ";
        case DT_FEATURE_1: return "FEATURE_1";
        case DT_POSFLAG_1: return "POSFLAG_1";
        case DT_SYMINSZ: return "SYMINSZ";
        case DT_SYMINENT: return "SYMINENT";
        case DT_GNU_HASH: return "GNU_HASH";
        case DT_TLSDESC_PLT: return "TLSDESC_PLT";
        case DT_TLSDESC_GOT: return "TLSDESC_GOT";
        case DT_GNU_CONFLICT: return "GNU_CONFLICT";
        case DT_GNU_LIBLIST: return "GNU_LIBLIST";
        case DT_CONFIG: return "CONFIG";
        case DT_DEPAUDIT: return "DEPAUDIT";
        case DT_AUDIT: return "AUDIT";
        case DT_PLTPAD: return "PLTPAD";
        case DT_MOVETAB: return "MOVETAB";
        case DT_SYMINFO: return "SYMINFO";
        case DT_RELACOUNT: return "RELACOUNT";
        case DT_RELCOUNT: return "RELCOUNT";
        case DT_FLAGS_1: return "FLAGS_1";
        case DT_VERDEF: return "VERDEF";
        case DT_VERDEFNUM: return "VERDEFNUM";
        case DT_VERNEED: return "VERNEED";
        case DT_VERNEEDNUM: return "VERNEEDNUM";
        case DT_VERSYM: return "VERSYM";
        case DT_AUXILIARY: return "AUXILIARY";
        case DT_USED: return "USED";
        case DT_FILTER: return "FILTER";
        case DT_REL: return "REL";
        case DT_RELA: return "RELA";

        default:
            static thread_local char buf[32];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_0x%" PRIx64, (uint64_t)tag);
            return buf;
    }
}


static void dt_flags_str(uint64_t flags, std::string& out){
    out.clear();
        if (flags & DF_ORIGIN)      out += "ORIGIN ";
        if (flags & DF_SYMBOLIC)    out += "SYMBOLIC ";
        if (flags & DF_TEXTREL)     out += "TEXTREL ";
        if (flags & DF_BIND_NOW)    out += "BIND_NOW ";
        if (flags & DF_STATIC_TLS)  out += "STATIC_TLS ";

        uint64_t remaining = flags & ~(DF_ORIGIN | DF_SYMBOLIC | DF_TEXTREL | DF_BIND_NOW | DF_STATIC_TLS);
        if (remaining) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_FLAGS_0x%" PRIx64 " ", remaining);
            out += buf;
        }
        if (!out.empty()) out.pop_back(); // remove trailing space
}

static void dt_flags_1_str(uint64_t flags, std::string& out) {
    out.clear();
    
    if (flags & DF_1_NOW)        out += "NOW ";
    if (flags & DF_1_GLOBAL)     out += "GLOBAL ";
    if (flags & DF_1_GROUP)      out += "GROUP ";
    if (flags & DF_1_NODELETE)   out += "NODELETE ";
    if (flags & DF_1_LOADFLTR)   out += "LOADFLTR ";
    if (flags & DF_1_INITFIRST)  out += "INITFIRST ";
    if (flags & DF_1_NOOPEN)     out += "NOOPEN ";
    if (flags & DF_1_ORIGIN)     out += "ORIGIN ";
    if (flags & DF_1_DIRECT)     out += "DIRECT ";
    if (flags & DF_1_TRANS)      out += "TRANS ";
    if (flags & DF_1_INTERPOSE)  out += "INTERPOSE ";
    if (flags & DF_1_NODEFLIB)   out += "NODEFLIB ";
    if (flags & DF_1_NODUMP)     out += "NODUMP ";
    if (flags & DF_1_CONFALT)    out += "CONFALT ";
    if (flags & DF_1_ENDFILTEE)  out += "ENDFILTEE ";
    if (flags & DF_1_DISPRELDNE) out += "DISPRELDNE ";
    if (flags & DF_1_DISPRELPND) out += "DISPRELPND ";
    if (flags & DF_1_NODIRECT)   out += "NODIRECT ";
    if (flags & DF_1_IGNMULDEF)  out += "IGNMULDEF ";
    if (flags & DF_1_NOKSYMS)    out += "NOKSYMS ";
    if (flags & DF_1_NOHDR)      out += "NOHDR ";
    if (flags & DF_1_EDITED)     out += "EDITED ";
    if (flags & DF_1_NORELOC)    out += "NORELOC ";
    if (flags & DF_1_SYMINTPOSE) out += "SYMINTPOSE ";
    if (flags & DF_1_GLOBAUDIT)  out += "GLOBAUDIT ";
    if (flags & DF_1_SINGLETON)  out += "SINGLETON ";
    if (flags & DF_1_STUB)       out += "STUB ";
    if (flags & DF_1_PIE)        out += "PIE ";
    if (flags & DF_1_KMOD)       out += "KMOD ";
    if (flags & DF_1_WEAKFILTER) out += "WEAKFILTER ";
    if (flags & DF_1_NOCOMMON)   out += "NOCOMMON ";

    uint64_t remaining = flags & ~(DF_1_NOW | DF_1_GLOBAL | DF_1_GROUP | DF_1_NODELETE | DF_1_LOADFLTR | 
        DF_1_INITFIRST | DF_1_NOOPEN | DF_1_ORIGIN | DF_1_DIRECT | DF_1_TRANS | DF_1_INTERPOSE | DF_1_NODEFLIB |
            DF_1_NODUMP | DF_1_CONFALT | DF_1_ENDFILTEE | DF_1_DISPRELDNE | DF_1_DISPRELPND | DF_1_NODIRECT |
            DF_1_IGNMULDEF | DF_1_NOKSYMS | DF_1_NOHDR | DF_1_EDITED | DF_1_NORELOC | DF_1_SYMINTPOSE | DF_1_GLOBAUDIT |
            DF_1_SINGLETON | DF_1_STUB | DF_1_PIE | DF_1_KMOD | DF_1_WEAKFILTER | DF_1_NOCOMMON);

    if (remaining)
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "UNKNOWN_FLAGS_1_0x%" PRIx64 " ", remaining);
        out += buf;
    }
    
    if (!out.empty()) out.pop_back(); // remove trailing space
}

static void dt_features_str(uint64_t features, std::string& out) {
    out.clear();
        if (features & DTF_1_PARINIT)   out += "PARINIT ";
        if (features & DTF_1_CONFEXP)   out += "CONFEXP ";

        if (features & ~(DTF_1_PARINIT | DTF_1_CONFEXP)) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_FEATURES_0x%" PRIx64 " ", features & ~(DTF_1_PARINIT | DTF_1_CONFEXP));
            out += buf;
        }

        if (!out.empty()) out.pop_back(); // remove trailing space
}

static void dt_posflag_str(uint64_t posflags, std::string& out) {
    out.clear();
        if (posflags & DF_P1_LAZYLOAD)  out += "LAZYLOAD ";
        if (posflags & DF_P1_GROUPPERM) out += "GROUPPERM ";

        uint64_t remaining = posflags & ~(DF_P1_LAZYLOAD | DF_P1_GROUPPERM);
        if (remaining) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_POSFLAGS_0x%" PRIx64 " ", remaining);
            out += buf;
        }

        if (!out.empty()) out.pop_back(); // remove trailing space
}

static void dt_gnu_flags_1_str(uint64_t gnu_flags_1, std::string& out) {
    out.clear();
    if (gnu_flags_1 & DF_GNU_1_UNIQUE)    out += "UNIQUE ";
    
    uint64_t remaining = gnu_flags_1 & ~(DF_GNU_1_UNIQUE);
    if (remaining) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "UNKNOWN_GNU_FLAGS_1_0x%" PRIx64 " ", remaining);
        out += buf;
    }
    if (!out.empty()) out.pop_back(); // remove trailing space
}

static void dt_pltrel_str(uint64_t pltrel, std::string& out) {
    out.clear();
    if (pltrel == DT_RELA) out += "RELA";
    if (pltrel == DT_REL)  out += "REL";
    
    if (pltrel != DT_RELA && pltrel != DT_REL) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "UNKNOWN_PLTREL_0x%" PRIx64, pltrel);
        out += buf;
    }
}

static DynSectionValueType dt_value_type(int64_t tag, uint16_t e_machine) {
    // --- ISA-specific tags ---------------------------------------------------

    if (e_machine == EM_AARCH64) {
        switch (tag) {
            case DT_AARCH64_BTI_PLT:  // on / off
            case DT_AARCH64_PAC_PLT:  // on / off
            case DT_AARCH64_MEMTAG_MODE: // 0 -> Synchronous, 1 -> Asynchronous
            case DT_AARCH64_MEMTAG_STACK: // 0 -> no tagging, 1 -> tag stack frames
            case DT_AARCH64_VARIANT_PCS: // Bitmask of PCS features
                return DynSectionValueType::DYN_VAL_NUM;
            default:
                break;
        }
    }
    else if (e_machine == EM_X86_64) {
        switch (tag) {
            case DT_X86_64_PLT: // Address of PLT
                return DynSectionValueType::DYN_VAL_ADDR;
            case DT_X86_64_PLTSZ: // Size of PLT
            case DT_X86_64_PLTENT: // Size of each PLT entry
                return DynSectionValueType::DYN_VAL_NUM;
            default:
                break;
        }
    }

    // --- Generic tags --------------------------------------------------------
    switch (tag) {
        // String-table offsets (need STRTAB)
        case DT_NEEDED:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RUNPATH:
        case DT_AUXILIARY:
        case DT_FILTER:
            return DynSectionValueType::DYN_VAL_STR;

        // Pointers / addresses
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        case DT_INIT:
        case DT_FINI:
        case DT_JMPREL:
        case DT_DEBUG:
        case DT_INIT_ARRAY:
        case DT_FINI_ARRAY:
        case DT_GNU_HASH:
        case DT_VERSYM:
        case DT_VERNEED:
        case DT_VERDEF:
        case DT_RELR:
        case DT_SYMTAB_SHNDX:
        case DT_PREINIT_ARRAY:
        case DT_TLSDESC_PLT:
        case DT_TLSDESC_GOT:
        case DT_GNU_CONFLICT:
        case DT_CONFIG:
        case DT_DEPAUDIT:
        case DT_AUDIT:
        case DT_PLTPAD:
        case DT_MOVETAB:
        case DT_SYMINFO:
        case DT_RELA:
        case DT_REL:
        case DT_GNU_LIBLIST:
            return DynSectionValueType::DYN_VAL_ADDR;

        // Flag sets
        case DT_FLAGS:          return DynSectionValueType::DYN_VAL_FLAGS;
        case DT_FLAGS_1:        return DynSectionValueType::DYN_VAL_FLAGS1;
        case DT_FEATURE_1:      return DynSectionValueType::DYN_VAL_FEATURES;
        case DT_POSFLAG_1:      return DynSectionValueType::DYN_VAL_POSFLAG1;
        case DT_PLTREL:       return DynSectionValueType::DYN_VAL_PLTREL;
        case DT_GNU_FLAGS_1:   return DynSectionValueType::DYN_VAL_GNU_FLAGS_1;

        // Sizes / counts / offsets
        // They can be handled by default case
        // ----------------------------------------------------
        // case DT_RELASZ:
        // case DT_RELAENT:
        // case DT_STRSZ:
        // case DT_SYMENT:
        // case DT_RELSZ:
        // case DT_RELENT:
        // case DT_TEXTREL:
        // case DT_BIND_NOW:
        // case DT_INIT_ARRAYSZ:
        // case DT_FINI_ARRAYSZ:
        // case DT_VERNEEDNUM:
        // case DT_VERDEFNUM:
        // case DT_NULL:
        // case DT_SYMBOLIC:
        // case DT_PREINIT_ARRAYSZ:
        // case DT_RELRSZ:
        // case DT_RELRENT:
        // case DT_GNU_PRELINKED:
        // case DT_GNU_CONFLICTSZ:
        // case DT_GNU_LIBLISTSZ:
        // case DT_CHECKSUM:
        // case DT_PLTPADSZ:
        // case DT_MOVEENT:
        // case DT_MOVESZ:
        // case DT_SYMINSZ:
        // case DT_SYMINENT: 
        // case DT_RELACOUNT:
        // case DT_RELCOUNT:
        //     return DynSectionValueType::DYN_VAL_NUM;

        default:
            return DynSectionValueType::DYN_VAL_NUM;
    }
}

template <typename PhdrT>
static void collect_segments(const uint8_t* data, size_t sz,
                             uint64_t phoff, uint16_t phentsize, uint16_t phnum, int swap,
                             std::vector< LoadSeg<PhdrT> >& loads,
                             const PhdrT*& dyn_phdr_out)
{
    dyn_phdr_out = nullptr;
    if (!in_bounds((size_t)phoff, (size_t)phentsize * (size_t)phnum, sz))
        throw std::runtime_error("Program headers out of bounds");

    const uint8_t* p = data + (size_t)phoff;
    for (uint16_t i = 0; i < phnum; ++i, p += phentsize) {
        const PhdrT* ph = reinterpret_cast<const PhdrT*>(p);
        uint32_t p_type =
            std::is_same<PhdrT, Elf64_Phdr>::value ? maybe32(((const Elf64_Phdr*)ph)->p_type, swap)
                                                   : maybe32(((const Elf32_Phdr*)ph)->p_type, swap);

        uint64_t p_offset = std::is_same<PhdrT, Elf64_Phdr>::value ? maybe64(((const Elf64_Phdr*)ph)->p_offset, swap)
                                                                   : maybe32(((const Elf32_Phdr*)ph)->p_offset, swap);
        uint64_t p_vaddr  = std::is_same<PhdrT, Elf64_Phdr>::value ? maybe64(((const Elf64_Phdr*)ph)->p_vaddr, swap)
                                                                   : maybe32(((const Elf32_Phdr*)ph)->p_vaddr, swap);
        uint64_t p_filesz = std::is_same<PhdrT, Elf64_Phdr>::value ? maybe64(((const Elf64_Phdr*)ph)->p_filesz, swap)
                                                                   : maybe32(((const Elf32_Phdr*)ph)->p_filesz, swap);
        uint64_t p_memsz  = std::is_same<PhdrT, Elf64_Phdr>::value ? maybe64(((const Elf64_Phdr*)ph)->p_memsz, swap)
                                                                   : maybe32(((const Elf32_Phdr*)ph)->p_memsz, swap);

        if (p_type == PT_LOAD) {
            loads.push_back(LoadSeg<PhdrT>{p_vaddr, p_memsz, p_offset, p_filesz});
        } else if (p_type == PT_DYNAMIC) {
            dyn_phdr_out = ph;
        }
    }
}

template <typename PhdrT>
static bool vaddr_to_offset(uint64_t vaddr,
                            const std::vector< LoadSeg<PhdrT> >& loads,
                            uint64_t& out_off)
{
    for (const auto& s : loads) {
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.memsz) {
            uint64_t delta = vaddr - s.vaddr;
            if (delta <= s.filesz) {
                out_off = s.off + delta;
                return true;
            }
        }
    }
    return false;
}

static void parse_dynamic_64(const uint8_t* data, size_t sz, int swap, std::vector<DynamicSectionInfo>& out){
    if (!in_bounds(0, sizeof(Elf64_Ehdr), sz)) throw std::runtime_error("Truncated ELF header");
    const Elf64_Ehdr* eh = (const Elf64_Ehdr*)data;

    uint64_t phoff = maybe64(eh->e_phoff, swap);
    uint16_t phentsize = maybe16(eh->e_phentsize, swap);
    uint16_t phnum = maybe16(eh->e_phnum, swap);
    if (phoff == 0 || phnum == 0) throw std::runtime_error("No program headers");

    std::vector< LoadSeg<Elf64_Phdr> > loads;
    const Elf64_Phdr* dyn_phdr = nullptr;
    collect_segments<Elf64_Phdr>(data, sz, phoff, phentsize, phnum, swap, loads, dyn_phdr);
    if (!dyn_phdr) throw std::runtime_error("No PT_DYNAMIC segment");

    uint64_t dyn_off   = maybe64(dyn_phdr->p_offset, swap);
    uint64_t dyn_filesz= maybe64(dyn_phdr->p_filesz, swap);
    if (!in_bounds((size_t)dyn_off, (size_t)dyn_filesz, sz))
        throw std::runtime_error("PT_DYNAMIC out of bounds");

    const uint8_t* p = data + (size_t)dyn_off;
    const uint8_t* end = p + (size_t)dyn_filesz;

    std::vector<RawDynEnt> raw;
    raw.reserve(64);

    uint64_t strtab_vaddr = 0, strsz = 0;

    while (p + sizeof(Elf64_Dyn) <= end) {
        const Elf64_Dyn* d = (const Elf64_Dyn*)p;
        int64_t d_tag  = (int64_t)maybe64((uint64_t)d->d_tag, swap);
        uint64_t d_un  = maybe64((uint64_t)d->d_un.d_val, swap);
        p += sizeof(Elf64_Dyn);

        if (d_tag == DT_NULL) break;
        raw.push_back({d_tag, d_un});

        if (d_tag == DT_STRTAB) strtab_vaddr = d_un;
        else if (d_tag == DT_STRSZ) strsz = d_un;
    }

    const char* strtab = nullptr;
    size_t strtab_sz = 0;
    if (strtab_vaddr && strsz) {
        uint64_t str_off;
        if (vaddr_to_offset<Elf64_Phdr>(strtab_vaddr, loads, str_off) &&
            in_bounds((size_t)str_off, (size_t)strsz, sz)) {
            strtab = (const char*)(data + (size_t)str_off);
            strtab_sz = (size_t)strsz;
        }
    }

    uint16_t e_machine = maybe16(eh->e_machine, swap);

    out.reserve(out.size() + raw.size());
    for (const auto& e : raw) {
        DynamicSectionInfo di;
        di.tag = dt_tag_name(e.tag, e_machine);
        di.val = e.val;
        di.val_type = dt_value_type(e.tag, e_machine);

        if (di.val_type == DynSectionValueType::DYN_VAL_STR && strtab && e.val < strtab_sz) {
            const char* cand = strtab + (size_t)e.val;
            size_t remain = strtab_sz - (size_t)e.val;
            size_t k = 0;
            for (; k < remain && cand[k] != '\0'; ++k) {}
            if (k < remain) di.val_str.assign(cand, k);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FLAGS)
        {
            dt_flags_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FLAGS1)
        {
            dt_flags_1_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FEATURES)
        {
            dt_features_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_POSFLAG1)
        {
            dt_posflag_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_PLTREL)
        {
            dt_pltrel_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_GNU_FLAGS_1)
        {
            dt_gnu_flags_1_str(e.val, di.val_str);
        }
        out.push_back(std::move(di));
    }
}

static void parse_dynamic_32(const uint8_t* data, size_t sz, int swap, std::vector<DynamicSectionInfo>& out){
    if (!in_bounds(0, sizeof(Elf32_Ehdr), sz)) throw std::runtime_error("Truncated ELF header");
    const Elf32_Ehdr* eh = (const Elf32_Ehdr*)data;

    uint32_t phoff = maybe32(eh->e_phoff, swap);
    uint16_t phentsize = maybe16(eh->e_phentsize, swap);
    uint16_t phnum = maybe16(eh->e_phnum, swap);
    if (phoff == 0 || phnum == 0) throw std::runtime_error("No program headers");

    std::vector< LoadSeg<Elf32_Phdr> > loads;
    const Elf32_Phdr* dyn_phdr = nullptr;
    collect_segments<Elf32_Phdr>(data, sz, phoff, phentsize, phnum, swap, loads, dyn_phdr);
    if (!dyn_phdr) throw std::runtime_error("No PT_DYNAMIC segment");

    uint32_t dyn_off   = maybe32(dyn_phdr->p_offset, swap);
    uint32_t dyn_filesz= maybe32(dyn_phdr->p_filesz, swap);
    if (!in_bounds((size_t)dyn_off, (size_t)dyn_filesz, sz))
        throw std::runtime_error("PT_DYNAMIC out of bounds");

    const uint8_t* p = data + (size_t)dyn_off;
    const uint8_t* end = p + (size_t)dyn_filesz;

    std::vector<RawDynEnt> raw;
    raw.reserve(64);

    uint64_t strtab_vaddr = 0, strsz = 0;

    while (p + sizeof(Elf32_Dyn) <= end) {
        const Elf32_Dyn* d = (const Elf32_Dyn*)p;
        int64_t d_tag  = (int64_t)maybe32((uint32_t)d->d_tag, swap);
        uint32_t d_un  = maybe32((uint32_t)d->d_un.d_val, swap);
        p += sizeof(Elf32_Dyn);

        if (d_tag == DT_NULL) break;
        raw.push_back({d_tag, (uint64_t)d_un});

        if (d_tag == DT_STRTAB) strtab_vaddr = d_un;
        else if (d_tag == DT_STRSZ) strsz = d_un;
    }

    const char* strtab = nullptr;
    size_t strtab_sz = 0;
    if (strtab_vaddr && strsz) {
        uint64_t str_off;
        if (vaddr_to_offset<Elf32_Phdr>(strtab_vaddr, loads, str_off) &&
            in_bounds((size_t)str_off, (size_t)strsz, sz)) {
            strtab = (const char*)(data + (size_t)str_off);
            strtab_sz = (size_t)strsz;
        }
    }

    uint16_t e_machine = maybe16(eh->e_machine, swap);

    out.reserve(out.size() + raw.size());
    for (const auto& e : raw) {
        DynamicSectionInfo di;
        di.tag = dt_tag_name(e.tag, e_machine);
        di.val = e.val;
        di.val_type = dt_value_type(e.tag, e_machine);

        if (di.val_type == DynSectionValueType::DYN_VAL_STR && strtab && e.val < strtab_sz) {
            const char* cand = strtab + (size_t)e.val;
            size_t remain = strtab_sz - (size_t)e.val;
            size_t k = 0;
            for (; k < remain && cand[k] != '\0'; ++k) {}
            if (k < remain) di.val_str.assign(cand, k);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FLAGS)
        {
            dt_flags_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FLAGS1)
        {
            dt_flags_1_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_FEATURES)
        {
            dt_features_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_POSFLAG1)
        {
            dt_posflag_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_PLTREL)
        {
            dt_pltrel_str(e.val, di.val_str);
        }
        else if (di.val_type == DynSectionValueType::DYN_VAL_GNU_FLAGS_1)
        {
            dt_gnu_flags_1_str(e.val, di.val_str);
        }
        out.push_back(std::move(di));
    }
}

static void internal_parse_elf_dynamic(const uint8_t* data, size_t sz, std::vector<DynamicSectionInfo>& out){
    if (sz < EI_NIDENT) throw std::runtime_error("File too small");
    if (!(data[0]==0x7f && data[1]=='E' && data[2]=='L' && data[3]=='F')) throw std::runtime_error("Not an ELF file");

    int file_le;
    switch (data[EI_DATA]) {
        case ELFDATA2LSB: file_le = 1; break;
        case ELFDATA2MSB: file_le = 0; break;
        default: throw std::runtime_error("Unknown ELF data encoding");
    }
    int swap = (file_le != host_is_le());

    int cls = data[EI_CLASS];
    if (cls == ELFCLASS64) {
        if (!in_bounds(0, sizeof(Elf64_Ehdr), sz)) throw std::runtime_error("Truncated ELF header (64)");
        parse_dynamic_64(data, sz, swap, out);
    } else if (cls == ELFCLASS32) {
        if (!in_bounds(0, sizeof(Elf32_Ehdr), sz)) throw std::runtime_error("Truncated ELF header (32)");
        parse_dynamic_32(data, sz, swap, out);
    } else {
        throw std::runtime_error("Unsupported ELF class");
    }
}

static const char* p_type_str(Elf64_Word p_type, uint16_t e_machine)
{
    if (e_machine == EM_AARCH64)
    {
        // AArch64 specific PT_* tags
        switch (p_type) {
            // Externally defined, no need for #ifdef
            case PT_AARCH64_ARCHEXT: return "AARCH64_ARCHEXT";
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
        case PT_SUNW_UNWIND: return "SUNW_UNWIND";
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK: return "GNU_STACK";
        case PT_GNU_RELRO: return "GNU_RELRO";
        case PT_GNU_PROPERTY: return "GNU_PROPERTY";
        case PT_GNU_SFRAME: return "GNU_SFRAME";
        case PT_OPENBSD_MUTABLE:   return "OPENBSD_MUTABLE";
        case PT_OPENBSD_RANDOMIZE: return "OPENBSD_RANDOMIZE";
        case PT_OPENBSD_WXNEEDED:  return "OPENBSD_WXNEEDED";
        case PT_OPENBSD_NOBTCFI:   return "OPENBSD_NOBTCFI";
        case PT_OPENBSD_SYSCALLS:  return "OPENBSD_SYSCALLS";
        case PT_OPENBSD_BOOTDATA:  return "OPENBSD_BOOTDATA";
        case PT_SUNWBSS: return "SUNWBSS";
        case PT_SUNWSTACK: return "SUNWSTACK";
        case PT_SUNWDTRACE: return "SUNWDTRACE";
        case PT_SUNWCAP: return "SUNWCAP";

        default:
            static thread_local char buf[32];
            std::snprintf(buf, sizeof(buf), "UNKNOWN 0x%" PRIx32, p_type);
            return buf;
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
    
    if (other) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), " | 0x%" PRIx32, other);
        out += buf;
    }
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
        info.type.assign(p_type_str(p_type, e_machine));
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
        info.type.assign(p_type_str(p_type, e_machine));
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

// -------------------- GNU property note parsing -------------------- //

static inline size_t align_up_sz(size_t x, size_t a) {
    return (a ? (x + a - 1) & ~(a - 1) : x);
}

static std::string join(const std::vector<const char*>& names) {
    std::string out;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) out += ' ';
        out += names[i];
    }
    if (out.empty()) out = "";
    return out;
}

static std::string decode_aarch64_feature_1_and(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) v.push_back("BTI");
    if (mask & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) v.push_back("PAC");
    if (mask & GNU_PROPERTY_AARCH64_FEATURE_1_GCS) v.push_back("GCS");

    uint32_t remaining = mask & ~(GNU_PROPERTY_AARCH64_FEATURE_1_BTI |
                                     GNU_PROPERTY_AARCH64_FEATURE_1_PAC |
                                     GNU_PROPERTY_AARCH64_FEATURE_1_GCS);
    if (remaining) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%" PRIx32, remaining);
        v.push_back(buf);
    }
    return join(v);
}

static std::string decode_x86_feature_1_and(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_X86_FEATURE_1_IBT)   v.push_back("IBT");
    if (mask & GNU_PROPERTY_X86_FEATURE_1_SHSTK) v.push_back("SHSTK");
    if (mask & GNU_PROPERTY_X86_FEATURE_1_LAM_U48) v.push_back("LAM_U48");
    if (mask & GNU_PROPERTY_X86_FEATURE_1_LAM_U57) v.push_back("LAM_U57");

    uint32_t remaining = mask & ~(GNU_PROPERTY_X86_FEATURE_1_IBT |
                                     GNU_PROPERTY_X86_FEATURE_1_SHSTK |
                                     GNU_PROPERTY_X86_FEATURE_1_LAM_U48 |
                                     GNU_PROPERTY_X86_FEATURE_1_LAM_U57);

    return join(v);
}

static std::string decode_x86_isa_1(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_X86_ISA_1_BASELINE) v.push_back("BASELINE");
    if (mask & GNU_PROPERTY_X86_ISA_1_V2)       v.push_back("V2");
    if (mask & GNU_PROPERTY_X86_ISA_1_V3)       v.push_back("V3");
    if (mask & GNU_PROPERTY_X86_ISA_1_V4)       v.push_back("V4");

    uint32_t remaining = mask & ~(GNU_PROPERTY_X86_ISA_1_BASELINE |
                                     GNU_PROPERTY_X86_ISA_1_V2 |
                                     GNU_PROPERTY_X86_ISA_1_V3 |
                                     GNU_PROPERTY_X86_ISA_1_V4);

    return join(v);
}

static std::string decode_x86_compat_isa_1(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_486)      v.push_back("486");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_586)      v.push_back("586");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_686)      v.push_back("686");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSE)        v.push_back("SSE");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSE2)       v.push_back("SSE2");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSE3)       v.push_back("SSE3");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSSE3)      v.push_back("SSSE3");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_1)     v.push_back("SSE4_1");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_2)     v.push_back("SSE4_2");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX)       v.push_back("AVX");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX2)      v.push_back("AVX2");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512F)   v.push_back("AVX512F");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512CD)  v.push_back("AVX512CD");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512ER)  v.push_back("AVX512ER");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512PF)  v.push_back("AVX512PF");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512VL)  v.push_back("AVX512VL");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512DQ)  v.push_back("AVX512DQ");
    if (mask & GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512BW)  v.push_back("AVX512BW");

    uint32_t remaining = mask & ~(GNU_PROPERTY_X86_COMPAT_ISA_1_486 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_586 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_686 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSE |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSE2 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSE3 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSSE3 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_1 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_2 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX2 |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512F |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512CD |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512ER |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512PF |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512VL |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512DQ |
                                     GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512BW);

    if (remaining) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%" PRIx32, remaining);
        v.push_back(buf);
    }

    return join(v);
}

static std::string decode_x86_feature_2_and(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_X86_FEATURE_2_X86) v.push_back("X86");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_X87) v.push_back("X87");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_MMX) v.push_back("MMX");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_XMM) v.push_back("XMM");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_YMM) v.push_back("YMM");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_ZMM) v.push_back("ZMM");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_FXSR) v.push_back("FXSR");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_XSAVE) v.push_back("XSAVE");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_XSAVEOPT) v.push_back("XSAVEOPT");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_XSAVEC) v.push_back("XSAVEC");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_TMM) v.push_back("TMM");
    if (mask & GNU_PROPERTY_X86_FEATURE_2_MASK) v.push_back("MASK");

    uint32_t remaining = mask & ~(GNU_PROPERTY_X86_FEATURE_2_X86 |
                                     GNU_PROPERTY_X86_FEATURE_2_MMX |
                                     GNU_PROPERTY_X86_FEATURE_2_X87 |
                                     GNU_PROPERTY_X86_FEATURE_2_XMM |
                                     GNU_PROPERTY_X86_FEATURE_2_YMM |
                                     GNU_PROPERTY_X86_FEATURE_2_ZMM |
                                     GNU_PROPERTY_X86_FEATURE_2_FXSR |
                                     GNU_PROPERTY_X86_FEATURE_2_XSAVE |
                                     GNU_PROPERTY_X86_FEATURE_2_XSAVEOPT |
                                     GNU_PROPERTY_X86_FEATURE_2_XSAVEC |
                                     GNU_PROPERTY_X86_FEATURE_2_TMM |
                                     GNU_PROPERTY_X86_FEATURE_2_MASK);

    if (remaining) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%" PRIx32, remaining);
        v.push_back(buf);
    }

    return join(v);
}

static std::string decode_x86_compat_2_isa_1(uint32_t mask) {
    std::vector<const char*> v;
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_CMOV) v.push_back("CMOV");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE) v.push_back("SSE");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE2) v.push_back("SSE2");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE3) v.push_back("SSE3");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSSE3) v.push_back("SSSE3");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_1) v.push_back("SSE4_1");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_2) v.push_back("SSE4_2");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX) v.push_back("AVX");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX2) v.push_back("AVX2");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_FMA) v.push_back("FMA");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512F) v.push_back("AVX512F");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512CD) v.push_back("AVX512CD");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512ER) v.push_back("AVX512ER");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512PF) v.push_back("AVX512PF");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512VL) v.push_back("AVX512VL");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512DQ) v.push_back("AVX512DQ");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512BW) v.push_back("AVX512BW");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4FMAPS) v.push_back("AVX512_4FMAPS");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4VNNIW) v.push_back("AVX512_4VNNIW");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BITALG) v.push_back("AVX512_BITALG");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_IFMA) v.push_back("AVX512_IFMA");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI) v.push_back("AVX512_VBMI");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI2) v.push_back("AVX512_VBMI2");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VNNI) v.push_back("AVX512_VNNI");
    if (mask & GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BF16) v.push_back("AVX512_BF16");

    uint32_t remaining = mask & ~(GNU_PROPERTY_X86_COMPAT_2_ISA_1_CMOV |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE2 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE3 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSSE3 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_1 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_2 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX2 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_FMA |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512F |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512CD |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512ER |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512PF |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512VL |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512DQ |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512BW |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4FMAPS |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4VNNIW |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BITALG |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_IFMA |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI2 |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VNNI |
                                     GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BF16);

    if (remaining) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%" PRIx32, remaining);
        v.push_back(buf);
    }

    return join(v);
}

static const char* gnu_property_type_str(uint32_t pr_type, uint16_t e_machine) {
    // Property types are in external defines, no need for #ifdef
    if (e_machine == EM_386 || e_machine == EM_X86_64) {
        // Arch-specific types (the *type*, not the bits):
        switch (pr_type) {
        case GNU_PROPERTY_X86_ISA_1_USED:             return "X86_ISA_1_USED";
        case GNU_PROPERTY_X86_ISA_1_NEEDED:           return "X86_ISA_1_NEEDED";
        case GNU_PROPERTY_X86_FEATURE_1_AND:          return "X86_FEATURE_1_AND";
        case GNU_PROPERTY_X86_COMPAT_ISA_1_USED:      return "X86_COMPAT_ISA_1_USED";
        case GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED:    return "X86_COMPAT_ISA_1_NEEDED";
        case GNU_PROPERTY_X86_FEATURE_2_NEEDED:          return "X86_FEATURE_2_NEEDED";
        case GNU_PROPERTY_X86_FEATURE_2_USED:           return "X86_FEATURE_2_USED";
        case GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED:    return "X86_COMPAT_2_ISA_1_NEEDED";
        case GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED:      return "X86_COMPAT_2_ISA_1_USED";
        default:
            // Fall through to generic handling below
            break;
        }
    }
    else if (e_machine == EM_AARCH64) {
        // Arch-specific types (the *type*, not the bits):
        if (pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND)
            return "AARCH64_FEATURE_1_AND";
    }
    
    switch (pr_type) {
        case GNU_PROPERTY_STACK_SIZE:             return "STACK_SIZE";
        case GNU_PROPERTY_NO_COPY_ON_PROTECTED:   return "NO_COPY_ON_PROTECTED";
        case GNU_PROPERTY_MEMORY_SEAL:            return "MEMORY_SEALS";
        case GNU_PROPERTY_1_NEEDED:               return "1_NEEDED";

        default: {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "UNKNOWN_0x%08x", pr_type);
            return strdup(buf);
        }
    }
}

static void parse_gnu_property_descs(const uint8_t* desc, size_t descsz, int swap,
                                     size_t prop_align, uint16_t e_machine,
                                     std::vector<GNUPropertyDescriptor>& out)
{
    const uint8_t* p = desc;
    const uint8_t* end = desc + descsz;

    while (p + 8 <= end) { // need pr_type (4) + pr_datasz (4)
        uint32_t pr_type = maybe32(*reinterpret_cast<const uint32_t*>(p), swap);
        uint32_t pr_datasz = maybe32(*reinterpret_cast<const uint32_t*>(p + 4), swap);
        p += 8;

        size_t padded = align_up_sz((size_t)pr_datasz, prop_align);
        if (p + padded > end) {
            // Malformed, stop to avoid over-read
            break;
        }

        GNUPropertyDescriptor pd;
        pd.type = gnu_property_type_str(pr_type, e_machine);
        pd.data.resize(pr_datasz);
        if (pr_datasz) {
            std::memcpy(pd.data.data(), p, pr_datasz);
        }
        // Decode known types
        if (pr_datasz == 4) {
            uint32_t mask = maybe32(*reinterpret_cast<const uint32_t*>(p), swap);
            
            if (e_machine == EM_AARCH64 && pr_type == GNU_PROPERTY_AARCH64_FEATURE_1_AND) {
                pd.is_bit_mask = true;
                pd.bit_mnemonics.assign(decode_aarch64_feature_1_and(mask));
            }
            else if (e_machine == EM_386 || e_machine == EM_X86_64)
            {
                // x86 and generic types
                switch (pr_type) {
                    case GNU_PROPERTY_X86_FEATURE_1_AND:
                        pd.is_bit_mask = true;
                        pd.bit_mnemonics.assign(decode_x86_feature_1_and(mask));
                        break;
                    case GNU_PROPERTY_X86_ISA_1_USED:
                    case GNU_PROPERTY_X86_ISA_1_NEEDED:
                        pd.is_bit_mask = false;
                        pd.bit_mnemonics.assign(decode_x86_isa_1(mask));
                        break;
                    case GNU_PROPERTY_X86_COMPAT_ISA_1_USED:
                    case GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED:
                        pd.is_bit_mask = true;
                        pd.bit_mnemonics.assign(decode_x86_compat_isa_1(mask));
                        break;
                    case GNU_PROPERTY_X86_FEATURE_2_NEEDED:
                    case GNU_PROPERTY_X86_FEATURE_2_USED:
                        pd.is_bit_mask = true;
                        pd.bit_mnemonics.assign(decode_x86_feature_2_and(mask));
                        break;
                    case GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED:
                    case GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED:
                        pd.is_bit_mask = true;
                        pd.bit_mnemonics.assign(decode_x86_compat_2_isa_1(mask));
                        break;
                    case GNU_PROPERTY_1_NEEDED:
                        pd.is_bit_mask = true;
                        if (mask & GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS)
                            pd.bit_mnemonics.assign("INDIRECT_EXTERN_ACCESS");
                        if (mask & ~GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS) {
                            if (!pd.bit_mnemonics.empty())
                                pd.bit_mnemonics.append(" ");
                            char buf[32];
                            std::snprintf(buf, sizeof(buf), "0x%" PRIx32, mask & ~GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS);
                            pd.bit_mnemonics.append(buf);
                        }
                    default:
                        pd.is_bit_mask = false;
                        pd.bit_mnemonics.assign("UNKNOWN_ARCH_SPECIFIC");
                        break;
                }   
            }
            else
            {
                pd.is_bit_mask = false;
                pd.bit_mnemonics.assign("UNKNOWN_ARCH_SPECIFIC");
            }
        }
        else
        {
            pd.is_bit_mask = false;
            pd.bit_mnemonics.clear();
        }

        out.push_back(std::move(pd));

        p += padded;
    }
}

static inline bool ranges_overlap(const void* a, size_t asz,
                                  const void* b, size_t bsz) {
    auto ab = reinterpret_cast<const uintptr_t>(a);
    auto ae = ab + asz;
    auto bb = reinterpret_cast<const uintptr_t>(b);
    auto be = bb + bsz;
    if (asz == 0 || bsz == 0) return false;
    return !(ae <= bb || be <= ab);
}

static void parse_gnu_property_notes_common(const uint8_t* data, size_t sz, int swap,
                                              const uint8_t* block, size_t block_size,
                                              bool is64, std::vector<GNUPropertyDescriptor>& out)
{
    // For note headers, the name/desc alignment is 4 regardless of class per gABI
    const size_t note_align = 4;
    const size_t prop_align = is64 ? 8 : 4; // alignment for individual GNU property entries

    uint16_t e_machine = 0;
    if (is64) {
        if (!in_bounds(0, sizeof(Elf64_Ehdr), sz)) throw std::runtime_error("Truncated ELF header");
        const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(data);
        e_machine = maybe16(eh->e_machine, swap);
    } else {
        if (!in_bounds(0, sizeof(Elf32_Ehdr), sz)) throw std::runtime_error("Truncated ELF header");
        const Elf32_Ehdr* eh = reinterpret_cast<const Elf32_Ehdr*>(data);
        e_machine = maybe16(eh->e_machine, swap);
    }

    const uint8_t* p = block;
    const uint8_t* end = block + block_size;

    while (p + sizeof(Elf32_Nhdr) <= end) { // Elf32_Nhdr and Elf64_Nhdr are identical layout
        // Read note header fields (always 32-bit)
        uint32_t namesz = maybe32(*reinterpret_cast<const uint32_t*>(p + 0), swap);
        uint32_t descsz = maybe32(*reinterpret_cast<const uint32_t*>(p + 4), swap);
        uint32_t n_type = maybe32(*reinterpret_cast<const uint32_t*>(p + 8), swap);
        p += 12;

        size_t namesz_a = align_up_sz((size_t)namesz, note_align);
        size_t descsz_a = align_up_sz((size_t)descsz, note_align);

        if (p + namesz_a + descsz_a > end) {
            // Malformed; stop parsing this block
            break;
        }

        const char* name = reinterpret_cast<const char*>(p);
        const bool is_gnu = (namesz >= 3) && (std::memcmp(name, "GNU", 3) == 0);
        const uint8_t* desc = p + namesz_a;

        // Only parse GNU property notes
        const bool good_type = (n_type == NT_GNU_PROPERTY_TYPE_0);
        if (is_gnu && good_type && descsz) {
            parse_gnu_property_descs(desc, (size_t)descsz, swap, prop_align, e_machine, out);
        }

        p += namesz_a + descsz_a;
    }
}

static void internal_parse_elf_property_notes(const uint8_t *data, size_t sz, 
                                                   const void* section_addr, const size_t section_size,
                                                   const void* segment_addr, const size_t segment_size,
                                                   std::vector<GNUPropertyDescriptor>& out) {

    if (!section_addr && !segment_addr) {
        out.clear();
        return; // Nothing to do
    }

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

    // If section_addr is not nullptr, it corresponds to the .note.gnu.property section
    // If segment_addr is not nullptr, it corresponds to a PT_GNU_PROPERTY segment

    int cls = data[EI_CLASS];
    bool is64 = (cls == ELFCLASS64);

    out.clear();

    const bool have_section = section_addr && section_size;
    const bool have_segment = segment_addr && segment_size;

    if (!have_section && !have_segment) return;

    // Prefer the section view when it exists.
    if (have_section)
        parse_gnu_property_notes_common(data, sz, swap,
                                        (const uint8_t*)section_addr, section_size,
                                        is64, out);

    // Only parse the segment if it does NOT overlap the section bytes.
    if (have_segment && !(have_section && ranges_overlap(section_addr, section_size,
                                                         segment_addr, segment_size))) {
        parse_gnu_property_notes_common(data, sz, swap,
                                        (const uint8_t*)segment_addr, segment_size,
                                        is64, out);
    }

}

static inline bool is_ascii_printable(uint8_t c) noexcept { return c >= 32 && c <= 126; }

// Output version (recommended)
static void internal_quick_sym_lookup(const uint8_t* data,
                                      size_t sz,
                                      const std::string& substr,
                                      std::vector<std::string>& out_syms) {
    if (!data || sz == 0) return;

    // Prebuild a fast searcher
    const auto searcher = std::boyer_moore_horspool_searcher(substr.begin(), substr.end());

    const uint8_t* p   = data;
    const uint8_t* end = data + sz;

    const uint8_t* run_start = nullptr;
    size_t run_len = 0;

    auto process_run = [&](const uint8_t* s, size_t n) {
        if (n < 3 || n < substr.size()) return;
        std::string_view sv(reinterpret_cast<const char*>(s), n);
        auto it = std::search(sv.begin(), sv.end(), searcher);
        if (it != sv.end()) {
            out_syms.emplace_back(sv); // one allocation only on hit
        }
    };

    while (p < end) {
        if (is_ascii_printable(*p)) {
            if (!run_start) run_start = p;
            ++run_len;
        } else {
            if (run_start) process_run(run_start, run_len);
            run_start = nullptr;
            run_len = 0;
        }
        ++p;
    }
    // Flush last run if buffer ends with printable bytes
    if (run_start) process_run(run_start, run_len);
}


// ---- Public API --------------------------------------------------------------

SectionTable SectionTable::parse_file(const char* filename){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    SectionTable tbl;
    internal_parse_elf_sections(buf.data(), buf.size(), tbl.sections);
    return tbl;
}

DynamicSectionTable DynamicSectionTable::parse_file(const char* filename){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    DynamicSectionTable tbl;
    internal_parse_elf_dynamic(buf.data(), buf.size(), tbl.entries);
    return tbl;
}

ProgramHeaderTable ProgramHeaderTable::parse_file(const char* filename){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    ProgramHeaderTable tbl;
    internal_parse_program_headers(buf.data(), buf.size(), tbl.headers);
    return tbl;
}

GNUPropertyNotesTable GNUPropertyNotesTable::parse_file(const char* filename,
                                                            const size_t section_off,
                                                            const size_t section_size,
                                                            const size_t segment_off,
                                                            const size_t segment_size){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    GNUPropertyNotesTable tbl;
    const uint8_t* base = buf.data();
    const size_t sz = buf.size();

    const void* section_ptr = nullptr;
    const void* segment_ptr = nullptr;

    if (section_off != 0 && section_size != 0) {
        if (!in_bounds(section_off, section_size, sz)) {
            throw std::runtime_error("GNUPropertyNotesTable: section range out of bounds");
        }
        section_ptr = base + section_off;
    }

    if (segment_off != 0 && segment_size != 0) {
        if (!in_bounds(segment_off, segment_size, sz)) {
            throw std::runtime_error("GNUPropertyNotesTable: segment range out of bounds");
        }
        segment_ptr = base + segment_off;
    }

    internal_parse_elf_property_notes(base, sz, section_ptr, section_size, segment_ptr, segment_size, tbl.properties);
    return tbl;
}

std::vector<std::string> quick_sym_heuristic_lookup(const char* filename, std::string substr) {
    std::vector<uint8_t> buf;
    std::vector<std::string> result;
    read_file_or_throw(filename, buf);

    internal_quick_sym_lookup(buf.data(), buf.size(), substr, result);
    return result;
}

namespace nb = nanobind;

NB_MODULE(libdebug_elf_api, m) {
    // Section (leaf object)
    nb::class_<SectionInfo>(m, "Section", "ELF section")
        .def_ro("index", &SectionInfo::index, "The section index")
        .def_ro("type", &SectionInfo::type, "The ELF sh_type mnemonic")
        .def_ro("flags", &SectionInfo::flags, "The ELF sh_flags parsed string")
        .def_ro("addr", &SectionInfo::addr, "The virtual address (sh_addr)")
        .def_ro("offset", &SectionInfo::offset, "The file offset (sh_offset)")
        .def_ro("size", &SectionInfo::size, "The section size in bytes (sh_size)")
        .def_ro("addralign", &SectionInfo::addralign, "The alignment (sh_addralign)")
        .def_ro("name", &SectionInfo::name, "The section name");

    // SectionTable (container)
    nb::class_<SectionTable>(m, "SectionTable", "Container for ELF sections")
        .def_prop_ro(
            "sections",
            [](const SectionTable& t) { return t.sections; },   // returns std::vector<Section>
            "List of sections")
        .def_static("from_file", &SectionTable::parse_file,
                    nb::arg("elf_file_path"),
                    "Parse sections from an ELF file and return a SectionTable");

     nb::enum_<DynSectionValueType>(m, "DynSectionValueType")
        .value("NONE", DynSectionValueType::DYN_VAL_NONE)
        .value("NUM", DynSectionValueType::DYN_VAL_NUM)
        .value("STR", DynSectionValueType::DYN_VAL_STR)
        .value("ADDR", DynSectionValueType::DYN_VAL_ADDR)
        .value("FLAGS", DynSectionValueType::DYN_VAL_FLAGS)
        .value("FLAGS1", DynSectionValueType::DYN_VAL_FLAGS1)
        .value("FEATURES", DynSectionValueType::DYN_VAL_FEATURES)
        .value("POSFLAG1", DynSectionValueType::DYN_VAL_POSFLAG1)
        .value("PLTREL", DynSectionValueType::DYN_VAL_PLTREL)
        .value("GNU_FLAGS_1", DynSectionValueType::DYN_VAL_GNU_FLAGS_1);

    nb::class_<DynamicSectionInfo>(m, "DynamicEntry", "ELF DT_* dynamic entry")
        .def_ro("tag", &DynamicSectionInfo::tag, "Human-readable DT_* name (or 'UNKNOWN')")
        .def_ro("val", &DynamicSectionInfo::val, "Raw d_un value")
        .def_ro("val_str", &DynamicSectionInfo::val_str, "Resolved string (if applicable)")
        .def_ro("val_type", &DynamicSectionInfo::val_type, "Type of value");

    nb::class_<DynamicSectionTable>(m, "DynamicSectionTable", "Container for ELF dynamic section entries")
        .def_prop_ro(
            "entries",
            [](const DynamicSectionTable& t) { return t.entries; },
            "List of DT_* entries in file order")
        .def_static("from_file", &DynamicSectionTable::parse_file,
                    nb::arg("elf_file_path"),
                    "Parse DT_* entries from an ELF file and return a DynamicSectionTable");

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

    nb::class_<GNUPropertyDescriptor>(m, "GNUPropertyDescriptor", "GNU property descriptor from .note.gnu.property or PT_GNU_PROPERTY")
        .def_ro("type", &GNUPropertyDescriptor::type, "Property type name")
        .def_ro("data", &GNUPropertyDescriptor::data, "Raw property data as bytes")
        .def_ro("is_bit_mask", &GNUPropertyDescriptor::is_bit_mask, "True if the data is a bitmask")
        .def_ro("bit_mnemonics", &GNUPropertyDescriptor::bit_mnemonics, "Decoded bit mnemonics if applicable");

    nb::class_<GNUPropertyNotesTable>(m, "GNUPropertyNotesTable", "Container for GNU property descriptors")
        .def_prop_ro(
            "properties",
            [](const GNUPropertyNotesTable& t) { return t.properties; },
            "List of GNU property descriptors")
        .def_static("from_file", &GNUPropertyNotesTable::parse_file,
                    nb::arg("elf_file_path"),
                    nb::arg("section_off"),
                    nb::arg("section_size"),
                    nb::arg("segment_off"),
                    nb::arg("segment_size"),
                    "Parse GNU property descriptors from an ELF file and return a GNUPropertyNotesTable. "
                    "If section_off/section_size is provided, it is used as the .note.gnu.property section (file offsets). "
                    "If segment_off/segment_size is provided, it is used as the PT_GNU_PROPERTY segment (file offsets).");

    m.def("quick_sym_heuristic_lookup", &quick_sym_heuristic_lookup,
          nb::arg("elf_file_path"),
          nb::arg("substring"),
          "Quickly search for printable symbols (as a string) containing the given substring in an ELF file and return a list of matches");
}
