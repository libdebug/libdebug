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
static void parse_sections_64(const uint8_t *data, size_t sz, int swap, std::vector<Section>& out);
static void parse_sections_32(const uint8_t *data, size_t sz, int swap, std::vector<Section>& out);

static void parse_sections_64(const uint8_t *data, size_t sz, int swap, std::vector<Section>& out){
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

        Section s;
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

static void parse_sections_32(const uint8_t *data, size_t sz, int swap, std::vector<Section>& out){
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

        Section s;
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

static void internal_parse_elf_sections(const uint8_t *data, size_t sz, std::vector<Section>& out){
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

// ---- Public API --------------------------------------------------------------

SectionTable SectionTable::parse_file(const char* filename){
    std::vector<uint8_t> buf;
    read_file_or_throw(filename, buf);

    SectionTable tbl;
    internal_parse_elf_sections(buf.data(), buf.size(), tbl.sections);
    return tbl;
}

namespace nb = nanobind;

NB_MODULE(libdebug_section_parser, m) {
    // Section (leaf object)
    nb::class_<Section>(m, "Section", "ELF section")
        .def_ro("index", &Section::index, "The section index")
        .def_ro("type", &Section::type, "The ELF sh_type value")
        .def_ro("flags", &Section::flags, "The ELF sh_flags parsed string")
        .def_ro("addr", &Section::addr, "The virtual address (sh_addr)")
        .def_ro("offset", &Section::offset, "The file offset (sh_offset)")
        .def_ro("size", &Section::size, "The section size in bytes (sh_size)")
        .def_ro("addralign", &Section::addralign, "The alignment (sh_addralign)")
        .def_ro("name", &Section::name, "The section name");

    // SectionTable (container)
    nb::class_<SectionTable>(m, "SectionTable", "Container for ELF sections")
        .def_prop_ro(
            "sections",
            [](const SectionTable& t) { return t.sections; },   // returns std::vector<Section>
            "List of sections")
        .def_static("from_file", &SectionTable::parse_file,
                    nb::arg("elf_file_path"),
                    "Parse sections from an ELF file and return a SectionTable");
}
