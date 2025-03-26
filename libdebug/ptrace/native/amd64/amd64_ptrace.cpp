//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "libdebug_ptrace_interface.h"
#include "amd64_ptrace.h"

#define DECLARE_NANOBIND
#include "x86_fpregs_xsave_layout.h"
#undef DECLARE_NANOBIND

namespace nb = nanobind;

void init_libdebug_ptrace_registers(nb::module_ &m) {
    nb::class_<PtraceRegsStruct>(m, "PtraceRegsStruct")
        .def_rw("r15", &PtraceRegsStruct::r15)
        .def_rw("r14", &PtraceRegsStruct::r14)
        .def_rw("r13", &PtraceRegsStruct::r13)
        .def_rw("r12", &PtraceRegsStruct::r12)
        .def_rw("rbp", &PtraceRegsStruct::rbp)
        .def_rw("rbx", &PtraceRegsStruct::rbx)
        .def_rw("r11", &PtraceRegsStruct::r11)
        .def_rw("r10", &PtraceRegsStruct::r10)
        .def_rw("r9", &PtraceRegsStruct::r9)
        .def_rw("r8", &PtraceRegsStruct::r8)
        .def_rw("rax", &PtraceRegsStruct::rax)
        .def_rw("rcx", &PtraceRegsStruct::rcx)
        .def_rw("rdx", &PtraceRegsStruct::rdx)
        .def_rw("rsi", &PtraceRegsStruct::rsi)
        .def_rw("rdi", &PtraceRegsStruct::rdi)
        .def_rw("orig_rax", &PtraceRegsStruct::orig_rax)
        .def_rw("rip", &PtraceRegsStruct::rip)
        .def_rw("cs", &PtraceRegsStruct::cs)
        .def_rw("eflags", &PtraceRegsStruct::eflags)
        .def_rw("rsp", &PtraceRegsStruct::rsp)
        .def_rw("ss", &PtraceRegsStruct::ss)
        .def_rw("fs_base", &PtraceRegsStruct::fs_base)
        .def_rw("gs_base", &PtraceRegsStruct::gs_base)
        .def_rw("ds", &PtraceRegsStruct::ds)
        .def_rw("es", &PtraceRegsStruct::es)
        .def_rw("fs", &PtraceRegsStruct::fs)
        .def_rw("gs", &PtraceRegsStruct::gs);

    init_fpregs_struct(m);
}
