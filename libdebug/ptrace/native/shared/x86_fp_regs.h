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

class PtraceFPRegsStruct
{
    private:
        void* fpregs_area;
        bool dirty;
        bool fresh;
        PtraceFPRegsStructDefinition definition;

    public:
        PtraceFPRegsStruct(PtraceFPRegsStructDefinition def);
        ~PtraceFPRegsStruct();

        void* get_area();
        size_t get_size();
        unsigned long get_type();

        bool is_dirty();
        void set_dirty(bool value);

        bool is_fresh();
        void set_fresh(bool value);

        bool has_xsave();

        std::array<Reg128, 8> &mmx();
        std::array<Reg80, 10> &legacy_st_space();
        std::array<Reg128, 16> &xmm0();
        std::array<Reg128, 16> &ymm0();
        std::array<Reg256, 16> &zmm0();
        std::array<Reg512, 16> &zmm1();
};

#ifdef DECLARE_NANOBIND
void init_fpregs_struct(nanobind::module_ &m)
{
    nb::class_<PtraceFPRegsStruct>(m, "PtraceFPRegsStruct")
        .def_prop_ro("type", &PtraceFPRegsStruct::get_type, "The type of the fpregs struct.")
        .def_prop_rw("dirty", &PtraceFPRegsStruct::is_dirty, &PtraceFPRegsStruct::set_dirty, "Whether the fpregs struct is dirty (needs to be written back).")
        .def_prop_rw("fresh", &PtraceFPRegsStruct::is_fresh, &PtraceFPRegsStruct::set_fresh, "Whether the fpregs struct is fresh (has been read from the process).")
        .def_prop_ro("mmx", &PtraceFPRegsStruct::mmx, "The MMX registers as an array of Reg128.")
        .def_prop_ro("legacy_st_space", &PtraceFPRegsStruct::legacy_st_space, "The legacy ST space as an array of Reg80.")
        .def_prop_ro("has_xsave", &PtraceFPRegsStruct::has_xsave, "Whether the current CPU supports XSAVE.")
        .def_prop_ro("xmm0", &PtraceFPRegsStruct::xmm0, "The XMM0 registers as an array of Reg128.")
        .def_prop_ro("ymm0", &PtraceFPRegsStruct::ymm0, "The YMM0 registers as an array of Reg128.")
        .def_prop_ro("zmm0", &PtraceFPRegsStruct::zmm0, "The ZMM0 registers as an array of Reg256.")
        .def_prop_ro("zmm1", &PtraceFPRegsStruct::zmm1, "The ZMM1 registers as an array of Reg512.");
}
#endif // DECLARE_NANOBIND
