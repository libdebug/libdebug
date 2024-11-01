//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "libdebug_ptrace_base.h"

#define INSTRUCTION_POINTER(regs) (regs->eip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFF00) | 0xCC)

#define SET_SYSCALL_NUMBER(regs, value) regs->eax

#define SET_SYSCALL_ARG0(regs, value) regs->ebx = value
#define SET_SYSCALL_ARG1(regs, value) regs->ecx = value
#define SET_SYSCALL_ARG2(regs, value) regs->edx = value
#define SET_SYSCALL_ARG3(regs, value) regs->esi = value
#define SET_SYSCALL_ARG4(regs, value) regs->edi = value
#define SET_SYSCALL_ARG5(regs, value) regs->ebp = value

#define GET_SYSCALL_RESULT(regs) regs->eax

#define SYSCALL_INSTRUCTION 0x80CD

struct PtraceRegsStruct
{
    unsigned long ebx;
    unsigned long ecx;
    unsigned long edx;
    unsigned long esi;
    unsigned long edi;
    unsigned long ebp;
    unsigned long eax;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
    unsigned long orig_eax;
    unsigned long eip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long esp;
    unsigned long ss;
};

void init_libdebug_ptrace_registers(nanobind::module_ &m);
