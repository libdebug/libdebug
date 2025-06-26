//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "x86_fp_regs.h"

#define MMX_OFFSET 32              // 32 bytes before the st_space, see sys/user.h for amd64 systems
#define MMX_LEGACY_OFFSET 28       // see sys/user.h for i386 systems
#define XMM0_OFFSET (32 + 16 * 8)  // 32 bytes before the st_space + 16 bytes for each of the 8 mmx registers

PtraceFPRegsStruct::PtraceFPRegsStruct(PtraceFPRegsStructDefinition def)
    :   fpregs_area(nullptr),
        dirty(false),
        fresh(false),
        definition(def)
{
    // Allocate memory for the fpregs area based on the definition size
    fpregs_area = calloc(definition.struct_size, 1);
    if (!fpregs_area) {
        throw std::runtime_error("Failed to allocate memory for fpregs area");
    }
}

PtraceFPRegsStruct::~PtraceFPRegsStruct()
{
    if (fpregs_area) {
        free(fpregs_area);
    }
}

void* PtraceFPRegsStruct::get_area()
{
    return fpregs_area;
}

size_t PtraceFPRegsStruct::get_size()
{
    return definition.struct_size;
}

unsigned long PtraceFPRegsStruct::get_type()
{
    return definition.type;
}

bool PtraceFPRegsStruct::is_dirty()
{
    return dirty;
}

void PtraceFPRegsStruct::set_dirty(bool value)
{
    dirty = value;
}

bool PtraceFPRegsStruct::is_fresh()
{
    return fresh;
}

void PtraceFPRegsStruct::set_fresh(bool value)
{
    fresh = value;
}

bool PtraceFPRegsStruct::has_xsave()
{
    return definition.has_xsave;
}

std::array<Reg128, 8> &PtraceFPRegsStruct::mmx()
{
    return *reinterpret_cast<std::array<Reg128, 8>*>(static_cast<char*>(fpregs_area) + MMX_OFFSET);
}

std::array<Reg80, 10> &PtraceFPRegsStruct::legacy_st_space()
{
    // The st_space is located at the start of the fpregs area
    return *reinterpret_cast<std::array<Reg80, 10>*>(static_cast<char*>(fpregs_area) + MMX_LEGACY_OFFSET);
}

std::array<Reg128, 16> &PtraceFPRegsStruct::xmm0()
{
    return *reinterpret_cast<std::array<Reg128, 16>*>(static_cast<char*>(fpregs_area) + XMM0_OFFSET);
}

std::array<Reg128, 16> &PtraceFPRegsStruct::ymm0()
{
    if (definition.avx_ymm0_offset == 0) {
        throw std::runtime_error("AVX YMM0 offset is not defined in the fpregs struct definition");
    }

    return *reinterpret_cast<std::array<Reg128, 16>*>(static_cast<char*>(fpregs_area) + definition.avx_ymm0_offset);
}

std::array<Reg256, 16> &PtraceFPRegsStruct::zmm0()
{
    if (definition.avx512_zmm0_offset == 0) {
        throw std::runtime_error("AVX512 ZMM0 offset is not defined in the fpregs struct definition");
    }

    return *reinterpret_cast<std::array<Reg256, 16>*>(static_cast<char*>(fpregs_area) + definition.avx512_zmm0_offset);
}

std::array<Reg512, 16> &PtraceFPRegsStruct::zmm1()
{
    if (definition.avx512_zmm1_offset == 0) {
        throw std::runtime_error("AVX512 ZMM1 offset is not defined in the fpregs struct definition");
    }

    return *reinterpret_cast<std::array<Reg512, 16>*>(static_cast<char*>(fpregs_area) + definition.avx512_zmm1_offset);
}
