// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "section_parser.h"

#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h> 

static int host_is_le(void) {
    uint16_t x = 1;
    return *(uint8_t*)&x == 1;
}

static uint16_t bswap16(uint16_t x){ return (uint16_t)((x<<8)|(x>>8)); }
static uint32_t bswap32(uint32_t x){ return ((x&0x000000FFu)<<24)|((x&0x0000FF00u)<<8)|((x&0x00FF0000u)>>8)|((x&0xFF000000u)>>24); }
static uint64_t bswap64(uint64_t x){
    return ((uint64_t)bswap32((uint32_t)(x&0xFFFFFFFFull))<<32) | (uint64_t)bswap32((uint32_t)(x>>32));
}
static uint16_t maybe16(uint16_t v, int swap){ return swap ? bswap16(v) : v; }
static uint32_t maybe32(uint32_t v, int swap){ return swap ? bswap32(v) : v; }
static uint64_t maybe64(uint64_t v, int swap){ return swap ? bswap64(v) : v; }

static int is_p2(uint64_t x){ return x && ((x & (x - 1)) == 0); }

static void flags_str(uint64_t f, char out[16]){
    char *p = out;
    if (f & SHF_WRITE)      *p++='W';
    if (f & SHF_ALLOC)      *p++='A';
    if (f & SHF_EXECINSTR)  *p++='X';
    if (f & SHF_MERGE)      *p++='M';
    if (f & SHF_STRINGS)    *p++='S';
    if (f & SHF_INFO_LINK)  *p++='I';
    if (f & SHF_LINK_ORDER) *p++='L';
    if (f & SHF_OS_NONCONFORMING) *p++='O';
    if (f & SHF_GROUP)      *p++='G';
    if (f & SHF_TLS)        *p++='T';
#ifdef SHF_COMPRESSED
    if (f & SHF_COMPRESSED) *p++='C';
#endif
#ifdef SHF_EXCLUDE
    if (f & SHF_EXCLUDE)    *p++='E';
#endif
    *p = '\0';
}

static void read_file_or_throw(const char *path, std::vector<uint8_t> &buf){
    FILE *f = fopen(path, "rb");
    if (!f) throw std::runtime_error("Failed to open ELF file for section parsing");
    if (fseek(f, 0, SEEK_END)) { fclose(f); throw std::runtime_error("fseek failed"); }
    long n = ftell(f);
    if (n < 0) { fclose(f); throw std::runtime_error("ftell failed"); }
    if (fseek(f, 0, SEEK_SET)) { fclose(f); throw std::runtime_error("fseek failed"); }
    buf.resize(n > 0 ? (size_t)n : 1);
    size_t rd = fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    if (rd != buf.size()) throw std::runtime_error("Short read");
}

static int in_bounds(size_t off, size_t len, size_t file_sz){
    if (off > file_sz) return 0;
    if (len > file_sz - off) return 0;
    return 1;
}

// Forward decls now take an output vector instead of printing
static void parse_sections_64(const uint8_t *data, size_t sz, int swap, std::vector<SectionInfo>& out);
static void parse_sections_32(const uint8_t *data, size_t sz, int swap, std::vector<SectionInfo>& out);

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
        s.type = sh_type;
        flags_str(sh_flags, s.flags); // convert to string
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

        if (sh_addralign && !is_p2(sh_addralign)) {
            // Keep it non-fatal: warn via stderr, continue
            std::fprintf(stderr, "Warn: section %u has non power-of-two sh_addralign=%" PRIu64 "\n", i, (uint64_t)sh_addralign);
        }

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
        s.type = sh_type;
        flags_str(sh_flags, s.flags); // convert to string
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

#define OLD_DT_LOOS	0x60000000
#define OLD_DT_HIOS     0x6fffffff

static const char* dt_tag_name(int64_t tag) {
    switch (tag) {
        case DT_NULL:        return "NULL";
        case DT_NEEDED:      return "NEEDED";
        case DT_PLTRELSZ:    return "PLTRELSZ";
        case DT_PLTGOT:      return "PLTGOT";
        case DT_HASH:        return "HASH";
        case DT_STRTAB:      return "STRTAB";
        case DT_SYMTAB:      return "SYMTAB";
        case DT_RELA:        return "RELA";
        case DT_RELASZ:      return "RELASZ";
        case DT_RELAENT:     return "RELAENT";
        case DT_STRSZ:       return "STRSZ";
        case DT_SYMENT:      return "SYMENT";
        case DT_INIT:        return "INIT";
        case DT_FINI:        return "FINI";
        case DT_SONAME:      return "SONAME";
        case DT_RPATH:       return "RPATH";
        case DT_SYMBOLIC:    return "SYMBOLIC";
        case DT_REL:         return "REL";
        case DT_RELSZ:       return "RELSZ";
        case DT_RELENT:      return "RELENT";
        case DT_PLTREL:      return "PLTREL";
        case DT_DEBUG:       return "DEBUG";
        case DT_TEXTREL:     return "TEXTREL";
        case DT_JMPREL:      return "JMPREL";
        case DT_BIND_NOW:    return "BIND_NOW";
        case DT_INIT_ARRAY:  return "INIT_ARRAY";
        case DT_FINI_ARRAY:  return "FINI_ARRAY";
        case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
        case DT_RUNPATH:      return "RUNPATH";
        case DT_FLAGS:        return "FLAGS";
        case DT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case DT_PREINIT_ARRAYSZ: return "PREINIT_ARRAYSZ";
        case DT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";
        case DT_RELRSZ:       return "RELRSZ";
        case DT_RELR:         return "RELR";
        case DT_RELRENT:      return "RELRENT";
        case DT_NUM:          return "NUM";
        case OLD_DT_LOOS:     return "OLD_LOOS";
        case DT_LOOS:         return "LOOS";
        case DT_HIOS:         return "HIOS";
        case DT_VALRNGLO:     return "VALRNGLO";
        case DT_VALRNGHI:     return "VALRNGHI";
        case DT_ADDRRNGLO:    return "ADDRRNGLO";
        case DT_GNU_HASH:     return "GNU_HASH";
        case DT_ADDRRNGHI:    return "ADDRRNGHI";
        case DT_VERSYM:       return "VERSYM";
        case DT_RELACOUNT:    return "RELACOUNT";
        case DT_RELCOUNT:     return "RELCOUNT";
        case DT_FLAGS_1:      return "FLAGS_1";
        case DT_VERDEF:       return "VERDEF";
        case DT_VERDEFNUM:    return "VERDEFNUM";
        case DT_VERNEED:      return "VERNEED";
        case DT_VERNEEDNUM:   return "VERNEEDNUM";
        case DT_AUXILIARY:   return "AUXILIARY";
        case DT_LOPROC:       return "LOPROC";
        case DT_HIPROC:       return "HIPROC";
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
    if (!out.empty()) out.pop_back(); // remove trailing space
}

static DynSectionValueType dt_value_type(int64_t tag) {
    switch (tag) {
        
        // String-table offsets (need STRTAB)
        case DT_NEEDED:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RUNPATH:
        case DT_AUXILIARY:
            return DynSectionValueType::DYN_VAL_STR;

        // Pointers / addresses
        case DT_PLTGOT:
        case DT_HASH:
        case DT_STRTAB:
        case DT_SYMTAB:
        case DT_RELA:
        case DT_INIT:
        case DT_FINI:
        case DT_REL:
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
            return DynSectionValueType::DYN_VAL_ADDR;

        // Sizes / counts / enums / flags
        case DT_PLTRELSZ:
        case DT_RELASZ:
        case DT_RELAENT:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELSZ:
        case DT_RELENT:
        case DT_PLTREL:
        case DT_TEXTREL:
        case DT_BIND_NOW:
        case DT_INIT_ARRAYSZ:
        case DT_FINI_ARRAYSZ:
        case DT_VERNEEDNUM:
        case DT_VERDEFNUM:
        case DT_NULL:
        case DT_SYMBOLIC:
        case DT_PREINIT_ARRAYSZ:
        case DT_RELRSZ:
        case DT_RELRENT:
        case DT_NUM:
        case OLD_DT_LOOS:
        case DT_LOOS:
        case DT_HIOS:
        case DT_VALRNGLO:
        case DT_VALRNGHI:
        case DT_ADDRRNGLO:
        case DT_ADDRRNGHI:
        case DT_RELACOUNT:
        case DT_RELCOUNT:
        case DT_LOPROC:
        case DT_HIPROC:
            return DynSectionValueType::DYN_VAL_NUM;
        case DT_FLAGS:
            return DynSectionValueType::DYN_VAL_FLAGS;
        case DT_FLAGS_1:
            return DynSectionValueType::DYN_VAL_FLAGS1;

        default:
            return DynSectionValueType::DYN_VAL_NUM; // sensible default
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

    out.reserve(out.size() + raw.size());
    for (const auto& e : raw) {
        DynamicSectionInfo di;
        di.tag = dt_tag_name(e.tag);
        di.val = e.val;
        di.val_type = dt_value_type(e.tag);

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

    out.reserve(out.size() + raw.size());
    for (const auto& e : raw) {
        DynamicSectionInfo di;
        di.tag = dt_tag_name(e.tag);
        di.val = e.val;
        di.val_type = dt_value_type(e.tag);

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

namespace nb = nanobind;

NB_MODULE(libdebug_section_parser, m) {
    // Section (leaf object)
    nb::class_<SectionInfo>(m, "Section", "ELF section")
        .def_ro("index", &SectionInfo::index, "The section index")
        .def_ro("type", &SectionInfo::type, "The ELF sh_type value")
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
        .value("FLAGS1", DynSectionValueType::DYN_VAL_FLAGS1);

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
}
