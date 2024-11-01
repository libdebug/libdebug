//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "libdebug_ptrace_base.h"

#define INSTRUCTION_POINTER(regs) (regs->rip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)

#define SET_SYSCALL_NUMBER(regs, value) regs->rax = value

#define SET_SYSCALL_ARG0(regs, value) regs->rdi = value
#define SET_SYSCALL_ARG1(regs, value) regs->rsi = value
#define SET_SYSCALL_ARG2(regs, value) regs->rdx = value
#define SET_SYSCALL_ARG3(regs, value) regs->r10 = value
#define SET_SYSCALL_ARG4(regs, value) regs->r8 = value
#define SET_SYSCALL_ARG5(regs, value) regs->r9 = value

#define GET_SYSCALL_RESULT(regs) regs->rax

#define SYSCALL_INSTRUCTION 0x050F

struct PtraceRegsStruct
{
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
    unsigned long fs_base;
    unsigned long gs_base;
    unsigned long ds;
    unsigned long es;
    unsigned long fs;
    unsigned long gs;
};

void init_libdebug_ptrace_registers(nanobind::module_ &m);
