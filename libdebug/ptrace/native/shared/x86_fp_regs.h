//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "fp_regs_definition.h"
#include "libdebug_ptrace_base.h"

namespace nb = nanobind;

#define MMX_OFFSET 32
#define XMM0_OFFSET (32 + 16 * 8)

class PtraceFPRegsStruct
{
    private:
        void* fpregs_area;
        bool dirty;
        bool fresh;
        PtraceFPRegsStructDefinition definition;

    public:
        PtraceFPRegsStruct(PtraceFPRegsStructDefinition def)
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

        ~PtraceFPRegsStruct()
        {
            if (fpregs_area) {
                free(fpregs_area);
            }
        }

        void* get_area() const
        {
            return fpregs_area;
        }

        size_t get_size() const
        {
            return definition.struct_size;
        }

        unsigned long get_type() const
        {
            return definition.type;
        }

        bool is_dirty() const
        {
            return dirty;
        }

        void set_dirty(bool value)
        {
            dirty = value;
        }

        bool is_fresh() const
        {
            return fresh;
        }

        void set_fresh(bool value)
        {
            fresh = value;
        }

        bool has_xsave() const
        {
            return definition.has_xsave;
        }

        std::array<Reg128, 8> &mmx()
        {
            return *reinterpret_cast<std::array<Reg128, 8>*>(static_cast<char*>(fpregs_area) + MMX_OFFSET);
        }

        std::array<Reg128, 16> &xmm0()
        {
            return *reinterpret_cast<std::array<Reg128, 16>*>(static_cast<char*>(fpregs_area) + XMM0_OFFSET);
        }

        std::array<Reg128, 16> &ymm0()
        {
            if (definition.avx_ymm0_offset == 0) {
                throw std::runtime_error("AVX YMM0 offset is not defined in the fpregs struct definition");
            }

            return *reinterpret_cast<std::array<Reg128, 16>*>(static_cast<char*>(fpregs_area) + definition.avx_ymm0_offset);
        }

        std::array<Reg256, 16> &zmm0()
        {
            if (definition.avx512_zmm0_offset == 0) {
                throw std::runtime_error("AVX512 ZMM0 offset is not defined in the fpregs struct definition");
            }

            return *reinterpret_cast<std::array<Reg256, 16>*>(static_cast<char*>(fpregs_area) + definition.avx512_zmm0_offset);
        }

        std::array<Reg512, 16> &zmm1()
        {
            if (definition.avx512_zmm1_offset == 0) {
                throw std::runtime_error("AVX512 ZMM1 offset is not defined in the fpregs struct definition");
            }

            return *reinterpret_cast<std::array<Reg512, 16>*>(static_cast<char*>(fpregs_area) + definition.avx512_zmm1_offset);
        }
};

#ifdef DECLARE_NANOBIND
void init_fpregs_struct(nanobind::module_ &m)
{
    nb::class_<PtraceFPRegsStruct>(m, "PtraceFPRegsStruct")
        .def_prop_ro("type", &PtraceFPRegsStruct::get_type, "The type of the fpregs struct.")
        .def_prop_rw("dirty", &PtraceFPRegsStruct::is_dirty, &PtraceFPRegsStruct::set_dirty, "Whether the fpregs struct is dirty (needs to be written back).")
        .def_prop_rw("fresh", &PtraceFPRegsStruct::is_fresh, &PtraceFPRegsStruct::set_fresh, "Whether the fpregs struct is fresh (has been read from the process).")
        .def_prop_ro("mmx", &PtraceFPRegsStruct::mmx, "The MMX registers as an array of Reg128.")
        .def_prop_ro("xmm0", &PtraceFPRegsStruct::xmm0, "The XMM0 registers as an array of Reg128.")
        .def_prop_ro("ymm0", &PtraceFPRegsStruct::ymm0, "The YMM0 registers as an array of Reg128.")
        .def_prop_ro("zmm0", &PtraceFPRegsStruct::zmm0, "The ZMM0 registers as an array of Reg256.")
        .def_prop_ro("zmm1", &PtraceFPRegsStruct::zmm1, "The ZMM1 registers as an array of Reg512.");
}
#endif // DECLARE_NANOBIND