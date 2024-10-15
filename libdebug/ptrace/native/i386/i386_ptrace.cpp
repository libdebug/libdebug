//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "libdebug_ptrace_interface.h"
#include "i386_ptrace.h"

#define DECLARE_NANOBIND
#include "x86_fpregs_xsave_layout.h"
#undef DECLARE_NANOBIND

namespace nb = nanobind;

void init_libdebug_ptrace_i386(nb::module_ &m) {
    nb::class_<PtraceRegsStruct>(m, "PtraceRegsStruct")
        .def_rw("ebx", &PtraceRegsStruct::ebx)
        .def_rw("ecx", &PtraceRegsStruct::ecx)
        .def_rw("edx", &PtraceRegsStruct::edx)
        .def_rw("esi", &PtraceRegsStruct::esi)
        .def_rw("edi", &PtraceRegsStruct::edi)
        .def_rw("ebp", &PtraceRegsStruct::ebp)
        .def_rw("eax", &PtraceRegsStruct::eax)
        .def_rw("ds", &PtraceRegsStruct::ds)
        .def_rw("es", &PtraceRegsStruct::es)
        .def_rw("fs", &PtraceRegsStruct::fs)
        .def_rw("gs", &PtraceRegsStruct::gs)
        .def_rw("orig_eax", &PtraceRegsStruct::orig_eax)
        .def_rw("eip", &PtraceRegsStruct::eip)
        .def_rw("cs", &PtraceRegsStruct::cs)
        .def_rw("eflags", &PtraceRegsStruct::eflags)
        .def_rw("esp", &PtraceRegsStruct::esp)
        .def_rw("ss", &PtraceRegsStruct::ss);

    init_fpregs_struct(m);
}
