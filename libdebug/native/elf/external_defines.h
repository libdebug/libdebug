//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

// -------------------- Feature Defines -------------------- //
// Many of these defines are not found in glibc's elf.h, or are
// only found in very recent versions. We define them here to
// avoid ifdef hell in the code.

#pragma once

#include <cstdint>

// -------------------- e_machine values -------------------- //

/* e_machine values */

#define EM_NONE		  0
#define EM_386		  3
#define EM_X86_64	 62
#define EM_AARCH64	183

// -------------------- e_ident[] indexes -------------------- //

#define EI_MAG0  0
#define ELFMAG0  0x7f

#define EI_MAG1  1
#define ELFMAG1  'E'

#define EI_MAG2  2
#define ELFMAG2  'L'

#define EI_MAG3  3
#define ELFMAG3  'F'

#define ELFMAG  "\177ELF"
#define SELFMAG 4

#define EI_CLASS 4
#define ELFCLASSNONE 0
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFCLASSNUM 3

#define EI_DATA 5
#define ELFDATANONE 0
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2
#define ELFDATANUM 3

#define EI_VERSION 6

#define EI_OSABI 7
#define ELFOSABI_NONE  0
#define ELFOSABI_SYSV  0
#define ELFOSABI_GNU  3
#define ELFOSABI_LINUX  ELFOSABI_GNU
#define ELFOSABI_ARM_AEABI 64
#define ELFOSABI_ARM 97

#define EI_ABIVERSION	8

#define EI_PAD		9
#define EI_DATA		5	
#define EI_NIDENT (16)

// -------------------- Basic Types -------------------- //

/* 32-bit ELF base types. */
typedef uint32_t	Elf32_Addr;
typedef uint16_t	Elf32_Half;
typedef uint32_t	Elf32_Off;
typedef int32_t	Elf32_Sword;
typedef uint32_t	Elf32_Word;
typedef uint16_t	Elf32_Versym;

/* 64-bit ELF base types. */
typedef uint64_t	Elf64_Addr;
typedef uint16_t	Elf64_Half;
typedef int16_t	Elf64_SHalf;
typedef uint64_t	Elf64_Off;
typedef int32_t	Elf64_Sword;
typedef uint32_t	Elf64_Word;
typedef uint64_t	Elf64_Xword;
typedef int64_t	Elf64_Sxword;
typedef uint16_t	Elf64_Versym;


typedef struct
{
  unsigned char	e_ident[EI_NIDENT];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off	e_phoff;
  Elf32_Off	e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;
  Elf64_Off	e_phoff;
  Elf64_Off	e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct elf32_shdr {
  Elf32_Word sh_name;
  Elf32_Word sh_type;
  Elf32_Word sh_flags;
  Elf32_Addr sh_addr;
  Elf32_Off	sh_offset;
  Elf32_Word sh_size;
  Elf32_Word sh_link;
  Elf32_Word sh_info;
  Elf32_Word sh_addralign;
  Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;
  Elf64_Word sh_type;
  Elf64_Xword sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  Elf64_Xword sh_size;
  Elf64_Word sh_link;
  Elf64_Word sh_info;
  Elf64_Xword sh_addralign;
  Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct
{
  Elf32_Sword	d_tag;
  union
    {
      Elf32_Word d_val;
      Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;

typedef struct
{
  Elf64_Sxword	d_tag;
  union
    {
      Elf64_Xword d_val;
      Elf64_Addr d_ptr;
    } d_un;
} Elf64_Dyn;


typedef struct
{
  Elf32_Word	p_type;
  Elf32_Off	p_offset;
  Elf32_Addr	p_vaddr;
  Elf32_Addr	p_paddr;
  Elf32_Word	p_filesz;
  Elf32_Word	p_memsz;
  Elf32_Word	p_flags;
  Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct
{
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off	p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  Elf64_Xword	p_filesz;
  Elf64_Xword	p_memsz;
  Elf64_Xword	p_align;
} Elf64_Phdr;

typedef struct
{
  Elf32_Word n_namesz;
  Elf32_Word n_descsz;
  Elf32_Word n_type;
} Elf32_Nhdr;

typedef struct
{
  Elf64_Word n_namesz;
  Elf64_Word n_descsz;
  Elf64_Word n_type;
} Elf64_Nhdr;

// -------------------- Program Header Types -------------------- //

#define PT_NULL		0
#define PT_LOAD		1
#define PT_DYNAMIC	2
#define PT_INTERP	3
#define PT_NOTE		4
#define PT_SHLIB	5
#define PT_PHDR		6
#define PT_TLS		7
#define	PT_NUM		8

#define PT_LOOS		0x60000000
#define PT_HIOS		0x6fffffff

#define PT_SUNW_UNWIND  (PT_LOOS + 0x464e550)
#define PT_GNU_EH_FRAME	(PT_LOOS + 0x474e550) 
#define PT_SUNW_EH_FRAME PT_GNU_EH_FRAME      
#define PT_GNU_STACK	(PT_LOOS + 0x474e551) 
#define PT_GNU_RELRO	(PT_LOOS + 0x474e552) 
#define PT_GNU_PROPERTY	(PT_LOOS + 0x474e553) 
#define PT_GNU_SFRAME	(PT_LOOS + 0x474e554) 

#define PT_OPENBSD_MUTABLE   (PT_LOOS + 0x5a3dbe5)  
#define PT_OPENBSD_RANDOMIZE (PT_LOOS + 0x5a3dbe6)  
#define PT_OPENBSD_WXNEEDED  (PT_LOOS + 0x5a3dbe7)  
#define PT_OPENBSD_NOBTCFI   (PT_LOOS + 0x5a3dbe8)  
#define PT_OPENBSD_SYSCALLS  (PT_LOOS + 0x5a3dbe9)  
#define PT_OPENBSD_BOOTDATA  (PT_LOOS + 0x5a41be6)  

#define PT_SUNWBSS	(PT_LOOS + 0xffffffa)
#define PT_SUNWSTACK	(PT_LOOS + 0xffffffb)
#define PT_SUNWDTRACE   (PT_LOOS + 0xffffffc)
#define PT_SUNWCAP      (PT_LOOS + 0xffffffd)

#define PT_GNU_MBIND_NUM 4096
#define PT_GNU_MBIND_LO (PT_LOOS + 0x474e555)
#define PT_GNU_MBIND_HI (PT_GNU_MBIND_LO + PT_GNU_MBIND_NUM - 1)

#define PT_LOPROC	0x70000000
#define PT_HIPROC	0x7FFFFFFF

#define PT_AARCH64_ARCHEXT 0x70000000
#define PT_AARCH64_MEMTAG_MTE 0x70000002

// -------------------- Program Header Flags -------------------- //

#define PF_X		(1 << 0)
#define PF_W		(1 << 1)
#define PF_R		(1 << 2)

#define PF_MASKOS	0x0FF00000
#define PF_MASKPROC	0xF0000000

// -------------------- Section Header Types -------------------- //

#define SHT_NULL	0
#define SHT_PROGBITS	1
#define SHT_SYMTAB	2
#define SHT_STRTAB	3
#define SHT_RELA	4
#define SHT_HASH	5
#define SHT_DYNAMIC	6
#define SHT_NOTE	7
#define SHT_NOBITS	8
#define SHT_REL		9
#define SHT_SHLIB	10
#define SHT_DYNSYM	11

#define SHT_INIT_ARRAY	  14
#define SHT_FINI_ARRAY	  15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP	  17
#define SHT_SYMTAB_SHNDX  18
#define SHT_RELR	  19

#define SHT_LOOS	0x60000000
#define SHT_HIOS	0x6fffffff

#define SHT_ANDROID_REL              0x60000001
#define SHT_ANDROID_RELA             0x60000002

#define SHT_GNU_INCREMENTAL_INPUTS   0x6fff4700 

#define SHT_LLVM_ODRTAB              0x6fff4c00 
#define SHT_LLVM_LINKER_OPTIONS      0x6fff4c01 
#define SHT_LLVM_ADDRSIG             0x6fff4c03 
#define SHT_LLVM_DEPENDENT_LIBRARIES 0x6fff4c04 
#define SHT_LLVM_SYMPART             0x6fff4c05 
#define SHT_LLVM_PART_EHDR           0x6fff4c06 
#define SHT_LLVM_PART_PHDR           0x6fff4c07 
#define SHT_LLVM_BB_ADDR_MAP_V0      0x6fff4c08 
#define SHT_LLVM_CALL_GRAPH_PROFILE  0x6fff4c09 
#define SHT_LLVM_BB_ADDR_MAP         0x6fff4c0a 
#define SHT_LLVM_OFFLOADING          0x6fff4c0b 
#define SHT_LLVM_LTO                 0x6fff4c0c 

#define SHT_ANDROID_RELR             0x6fffff00

#define SHT_GNU_SFRAME		     0x6ffffff4
#define SHT_GNU_ATTRIBUTES           0x6ffffff5
#define SHT_GNU_HASH	             0x6ffffff6
#define SHT_GNU_LIBLIST	             0x6ffffff7
#define SHT_CHECKSUM	             0x6ffffff8
#define SHT_GNU_OBJECT_ONLY	     0x6ffffff9

#define SHT_GNU_verdef	0x6ffffffd
#define SHT_GNU_verneed	0x6ffffffe
#define SHT_GNU_versym	0x6fffffff

#define SHT_SUNW_COMDAT 0x6ffffffb
#define SHT_SUNW_move 0x6ffffffa
#define SHT_SUNW_syminfo 0x6ffffffc

#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7FFFFFFF

#define SHT_LOUSER	0x80000000

#define SHT_HIUSER	0xFFFFFFFF

#define SHT_X86_64_UNWIND 0x70000001
#define SHT_AARCH64_ATTRIBUTES 0x70000003
#define SHT_AARCH64_AUTH_RELR 0x70000004
#define SHT_AARCH64_MEMTAG_GLOBALS_STATIC 0x70000007
#define SHT_AARCH64_MEMTAG_GLOBALS_DYNAMIC 0x70000008

// -------------------- Section Header Flags -------------------- //

#define SHF_WRITE	(1 << 0)
#define SHF_ALLOC	(1 << 1)
#define SHF_EXECINSTR	(1 << 2)
#define SHF_MERGE	(1 << 4)
#define SHF_STRINGS	(1 << 5)
#define SHF_INFO_LINK	(1 << 6)
#define SHF_LINK_ORDER	(1 << 7)
#define SHF_OS_NONCONFORMING (1 << 8)
#define SHF_GROUP	(1 << 9)
#define SHF_TLS		(1 << 10)
#define SHF_COMPRESSED	(1 << 11)

#define SHF_MASKOS	0x0FF00000
#define SHF_GNU_RETAIN	(1 << 21)
#define SHF_GNU_MBIND	(1 << 24)

#define SHF_MASKPROC	0xF0000000

#define SHF_EXCLUDE	(1U << 31)

#define SHF_X86_64_LARGE 0x10000000

// ARM only
#define SHF_ENTRYSECT 0x10000000
#define SHF_COMDEF 0x80000000

// -------------------- GNU Property Section Defines -------------------- //
#define NOTE_GNU_PROPERTY_SECTION_NAME	".note.gnu.property"

#define GNU_PROPERTY_STACK_SIZE			1
#define GNU_PROPERTY_NO_COPY_ON_PROTECTED	2
#define GNU_PROPERTY_MEMORY_SEAL		3

#define GNU_PROPERTY_UINT32_AND_LO	0xb0000000
#define GNU_PROPERTY_UINT32_AND_HI	0xb0007fff

#define GNU_PROPERTY_UINT32_OR_LO	0xb0008000
#define GNU_PROPERTY_UINT32_OR_HI	0xb000ffff

#define GNU_PROPERTY_1_NEEDED		GNU_PROPERTY_UINT32_OR_LO

#define GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS	(1U << 0)

#define GNU_PROPERTY_LOPROC  0xc0000000

#define GNU_PROPERTY_HIPROC  0xdfffffff

#define GNU_PROPERTY_LOUSER  0xe0000000

#define GNU_PROPERTY_HIUSER  0xffffffff

#define GNU_PROPERTY_X86_COMPAT_ISA_1_USED	0xc0000000
#define GNU_PROPERTY_X86_COMPAT_ISA_1_NEEDED	0xc0000001

#define GNU_PROPERTY_X86_COMPAT_ISA_1_486	(1U << 0)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_586	(1U << 1)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_686	(1U << 2)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSE	(1U << 3)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSE2	(1U << 4)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSE3	(1U << 5)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSSE3	(1U << 6)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_1	(1U << 7)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_SSE4_2	(1U << 8)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX	(1U << 9)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX2	(1U << 10)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512F	(1U << 11)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512CD	(1U << 12)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512ER	(1U << 13)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512PF	(1U << 14)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512VL	(1U << 15)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512DQ	(1U << 16)
#define GNU_PROPERTY_X86_COMPAT_ISA_1_AVX512BW	(1U << 17)

#define GNU_PROPERTY_X86_UINT32_AND_LO		0xc0000002
#define GNU_PROPERTY_X86_UINT32_AND_HI		0xc0007fff

#define GNU_PROPERTY_X86_UINT32_OR_LO		0xc0008000
#define GNU_PROPERTY_X86_UINT32_OR_HI		0xc000ffff

#define GNU_PROPERTY_X86_UINT32_OR_AND_LO	0xc0010000
#define GNU_PROPERTY_X86_UINT32_OR_AND_HI	0xc0017fff

#define GNU_PROPERTY_X86_FEATURE_1_AND \
  (GNU_PROPERTY_X86_UINT32_AND_LO + 0)

#define GNU_PROPERTY_X86_ISA_1_NEEDED \
  (GNU_PROPERTY_X86_UINT32_OR_LO + 2)
#define GNU_PROPERTY_X86_FEATURE_2_NEEDED \
  (GNU_PROPERTY_X86_UINT32_OR_LO + 1)

#define GNU_PROPERTY_X86_ISA_1_USED \
  (GNU_PROPERTY_X86_UINT32_OR_AND_LO + 2)
#define GNU_PROPERTY_X86_FEATURE_2_USED \
  (GNU_PROPERTY_X86_UINT32_OR_AND_LO + 1)

#define GNU_PROPERTY_X86_ISA_1_BASELINE		(1U << 0)
#define GNU_PROPERTY_X86_ISA_1_V2		(1U << 1)
#define GNU_PROPERTY_X86_ISA_1_V3		(1U << 2)
#define GNU_PROPERTY_X86_ISA_1_V4		(1U << 3)

#define GNU_PROPERTY_X86_FEATURE_1_IBT		(1U << 0)
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK	(1U << 1)
#define GNU_PROPERTY_X86_FEATURE_1_LAM_U48	(1U << 2)
#define GNU_PROPERTY_X86_FEATURE_1_LAM_U57	(1U << 3)

#define GNU_PROPERTY_X86_FEATURE_2_X86		(1U << 0)
#define GNU_PROPERTY_X86_FEATURE_2_X87		(1U << 1)
#define GNU_PROPERTY_X86_FEATURE_2_MMX		(1U << 2)
#define GNU_PROPERTY_X86_FEATURE_2_XMM		(1U << 3)
#define GNU_PROPERTY_X86_FEATURE_2_YMM		(1U << 4)
#define GNU_PROPERTY_X86_FEATURE_2_ZMM		(1U << 5)
#define GNU_PROPERTY_X86_FEATURE_2_FXSR		(1U << 6)
#define GNU_PROPERTY_X86_FEATURE_2_XSAVE	(1U << 7)
#define GNU_PROPERTY_X86_FEATURE_2_XSAVEOPT	(1U << 8)
#define GNU_PROPERTY_X86_FEATURE_2_XSAVEC	(1U << 9)
#define GNU_PROPERTY_X86_FEATURE_2_TMM		(1U << 10)
#define GNU_PROPERTY_X86_FEATURE_2_MASK		(1U << 11)

#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_NEEDED \
  (GNU_PROPERTY_X86_UINT32_OR_LO + 0)

#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_USED \
  (GNU_PROPERTY_X86_UINT32_OR_AND_LO + 0)

#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_CMOV		(1U << 0)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE		(1U << 1)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE2		(1U << 2)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE3		(1U << 3)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSSE3		(1U << 4)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_1		(1U << 5)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_SSE4_2		(1U << 6)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX		(1U << 7)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX2		(1U << 8)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_FMA		(1U << 9)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512F		(1U << 10)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512CD	(1U << 11)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512ER	(1U << 12)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512PF	(1U << 13)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512VL	(1U << 14)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512DQ	(1U << 15)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512BW	(1U << 16)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4FMAPS	(1U << 17)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_4VNNIW	(1U << 18)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BITALG	(1U << 19)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_IFMA	(1U << 20)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI	(1U << 21)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VBMI2	(1U << 22)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_VNNI	(1U << 23)
#define GNU_PROPERTY_X86_COMPAT_2_ISA_1_AVX512_BF16	(1U << 24)

#define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000

#define GNU_PROPERTY_AARCH64_FEATURE_1_BTI	(1U << 0)
#define GNU_PROPERTY_AARCH64_FEATURE_1_PAC	(1U << 1)
#define GNU_PROPERTY_AARCH64_FEATURE_1_GCS	(1U << 2)

// -------------------- Note Section Defines -------------------- //
#define NT_GNU_ABI_TAG	1
#define NT_GNU_HWCAP	2
#define NT_GNU_BUILD_ID	3
#define NT_GNU_GOLD_VERSION	4
#define NT_GNU_PROPERTY_TYPE_0 5

// -------------------- Dynamic Section Tags -------------------- //

#define DT_NULL		0
#define DT_NEEDED	1
#define DT_PLTRELSZ	2
#define DT_PLTGOT	3
#define DT_HASH		4
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_STRSZ	10
#define DT_SYMENT	11
#define DT_INIT		12
#define DT_FINI		13
#define DT_SONAME	14
#define DT_RPATH	15
#define DT_SYMBOLIC	16
#define DT_REL		17
#define DT_RELSZ	18
#define DT_RELENT	19
#define DT_PLTREL	20
#define DT_DEBUG	21
#define DT_TEXTREL	22
#define DT_JMPREL	23
#define DT_BIND_NOW	24
#define DT_INIT_ARRAY	25
#define DT_FINI_ARRAY	26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH	29
#define DT_FLAGS	30

#define DT_ENCODING	32
#define DT_PREINIT_ARRAY   32
#define DT_PREINIT_ARRAYSZ 33
#define DT_SYMTAB_SHNDX    34
#define DT_RELRSZ	35
#define DT_RELR		36
#define DT_RELRENT	37

#define OLD_DT_LOOS	0x60000000
#define DT_LOOS		0x6000000d
#define DT_HIOS		0x6ffff000
#define OLD_DT_HIOS	0x6fffffff

#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

#define DT_VALRNGLO	0x6ffffd00
#define DT_GNU_FLAGS_1  0x6ffffdf4
#define DT_GNU_PRELINKED 0x6ffffdf5
#define DT_GNU_CONFLICTSZ 0x6ffffdf6
#define DT_GNU_LIBLISTSZ 0x6ffffdf7
#define DT_CHECKSUM	0x6ffffdf8
#define DT_PLTPADSZ	0x6ffffdf9
#define DT_MOVEENT	0x6ffffdfa
#define DT_MOVESZ	0x6ffffdfb
#define DT_FEATURE_1	0x6ffffdfc
#define DT_POSFLAG_1	0x6ffffdfd
#define DT_SYMINSZ	0x6ffffdfe
#define DT_SYMINENT	0x6ffffdff
#define DT_VALRNGHI	0x6ffffdff

#define DT_ADDRRNGLO	0x6ffffe00
#define DT_GNU_HASH	0x6ffffef5
#define DT_TLSDESC_PLT	0x6ffffef6
#define DT_TLSDESC_GOT	0x6ffffef7
#define DT_GNU_CONFLICT	0x6ffffef8
#define DT_GNU_LIBLIST	0x6ffffef9
#define DT_CONFIG	0x6ffffefa
#define DT_DEPAUDIT	0x6ffffefb
#define DT_AUDIT	0x6ffffefc
#define DT_PLTPAD	0x6ffffefd
#define DT_MOVETAB	0x6ffffefe
#define DT_SYMINFO	0x6ffffeff
#define DT_ADDRRNGHI	0x6ffffeff

#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERDEF	0x6ffffffc
#define DT_VERDEFNUM	0x6ffffffd
#define DT_VERNEED	0x6ffffffe
#define DT_VERNEEDNUM	0x6fffffff

#define DT_VERSYM	0x6ffffff0

#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

#define DT_AUXILIARY	0x7ffffffd
#define DT_USED		0x7ffffffe
#define DT_FILTER	0x7fffffff


#define DT_X86_64_PLT 0x70000000
#define DT_X86_64_PLTSZ 0x70000001
#define DT_X86_64_PLTENT 0x70000003

#define DT_AARCH64_BTI_PLT 0x70000001
#define DT_AARCH64_PAC_PLT 0x70000003
#define DT_AARCH64_VARIANT_PCS 0x70000005
#define DT_AARCH64_MEMTAG_MODE 0x70000009
#define DT_AARCH64_MEMTAG_STACK 0x7000000C

// -------------------- Dynamic Section Flags -------------------- //
#define DF_ORIGIN	(1 << 0)
#define DF_SYMBOLIC	(1 << 1)
#define DF_TEXTREL	(1 << 2)
#define DF_BIND_NOW	(1 << 3)
#define DF_STATIC_TLS	(1 << 4)

// -------------------- Dynamic Section Feature 1 Flags -------------------- //

#define DTF_1_PARINIT	0x00000001
#define DTF_1_CONFEXP	0x00000002

// -------------------- Dynamic Section Posflag 1 Flags -------------------- //

#define DF_P1_LAZYLOAD	0x00000001
#define DF_P1_GROUPPERM	0x00000002

// -------------------- Dynamic Section GNU Flags 1 -------------------- //

#define DF_GNU_1_UNIQUE 0x00000001

// -------------------- Dynamic Section Flags 1 -------------------- //

#define DF_1_NOW	0x00000001
#define DF_1_GLOBAL	0x00000002
#define DF_1_GROUP	0x00000004
#define DF_1_NODELETE	0x00000008
#define DF_1_LOADFLTR	0x00000010
#define DF_1_INITFIRST	0x00000020
#define DF_1_NOOPEN	0x00000040
#define DF_1_ORIGIN	0x00000080
#define DF_1_DIRECT	0x00000100
#define DF_1_TRANS	0x00000200
#define DF_1_INTERPOSE	0x00000400
#define DF_1_NODEFLIB	0x00000800
#define DF_1_NODUMP	0x00001000
#define DF_1_CONFALT	0x00002000
#define DF_1_ENDFILTEE	0x00004000
#define	DF_1_DISPRELDNE	0x00008000
#define	DF_1_DISPRELPND	0x00010000
#define	DF_1_NODIRECT	0x00020000
#define	DF_1_IGNMULDEF	0x00040000
#define	DF_1_NOKSYMS	0x00080000
#define	DF_1_NOHDR	0x00100000
#define	DF_1_EDITED	0x00200000
#define	DF_1_NORELOC	0x00400000
#define	DF_1_SYMINTPOSE	0x00800000
#define	DF_1_GLOBAUDIT	0x01000000
#define	DF_1_SINGLETON	0x02000000
#define	DF_1_STUB	0x04000000
#define	DF_1_PIE	0x08000000
#define	DF_1_KMOD	0x10000000
#define	DF_1_WEAKFILTER	0x20000000
#define	DF_1_NOCOMMON	0x40000000

// -------------------- Special Section Indices -------------------- //
#define SHN_XINDEX 0xffff

// -------------------- Special Program Header Numbers -------------------- //
#define PN_XNUM		0xffff