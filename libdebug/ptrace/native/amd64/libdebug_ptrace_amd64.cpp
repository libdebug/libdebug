//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <elf.h>
#include <nanobind/nanobind.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include "../libdebug_ptrace_interface.h"
#include "libdebug_ptrace_amd64.h"

namespace nb = nanobind;


int IS_CALL_INSTRUCTION(uint8_t* instr)
{
    // Check for direct CALL (E8 xx xx xx xx)
    if (instr[0] == (uint8_t)0xE8) {
        return 1; // It's a CALL
    }

    // Check for indirect CALL using ModR/M (FF /2)
    if (instr[0] == (uint8_t)0xFF) {
        // Extract ModR/M byte
        uint8_t modRM = (uint8_t)instr[1];
        uint8_t reg = (modRM >> 3) & 7; // Middle three bits

        if (reg == 2) {
            return 1; // It's a CALL
        }
    }

    return 0; // Not a CALL
}


void LibdebugPtraceInterface::arch_getfpregs(Thread &t)
{
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, padding0);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, padding0);

    if (ptrace(PTRACE_GETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
        throw std::runtime_error("ptrace getregset xstate failed");
    }
}

void LibdebugPtraceInterface::arch_setfpregs(Thread &t)
{
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, padding0);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, padding0);

    if (ptrace(PTRACE_SETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
        throw std::runtime_error("ptrace setregset xstate failed");
    }
}


void init_libdebug_ptrace_amd64(nb::module_ &m) {
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

    nb::class_<PtraceFPRegsStruct>(m, "PtraceFPRegsStruct")
    .def_ro("type", &PtraceFPRegsStruct::type)
    .def_rw("dirty", &PtraceFPRegsStruct::dirty)
    .def_rw("fresh", &PtraceFPRegsStruct::fresh)
    .def_ro("mmx", &PtraceFPRegsStruct::mmx)
    .def_ro("xmm0", &PtraceFPRegsStruct::xmm0)
    .def_ro("ymm0", &PtraceFPRegsStruct::ymm0);
}
