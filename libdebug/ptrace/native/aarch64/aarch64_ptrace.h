//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "libdebug_ptrace_base.h"

#define INSTRUCTION_POINTER(regs) (regs->pc)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFF00000000) | 0xD4200000)
#define BREAKPOINT_SIZE 4
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xD4200000)

#define IS_RET_INSTRUCTION(instruction) (instruction == 0xD65F03C0)

int IS_CALL_INSTRUCTION(uint8_t* instr);

struct PtraceRegsStruct
{
    unsigned long x0;
    unsigned long x1;
    unsigned long x2;
    unsigned long x3;
    unsigned long x4;
    unsigned long x5;
    unsigned long x6;
    unsigned long x7;
    unsigned long x8;
    unsigned long x9;
    unsigned long x10;
    unsigned long x11;
    unsigned long x12;
    unsigned long x13;
    unsigned long x14;
    unsigned long x15;
    unsigned long x16;
    unsigned long x17;
    unsigned long x18;
    unsigned long x19;
    unsigned long x20;
    unsigned long x21;
    unsigned long x22;
    unsigned long x23;
    unsigned long x24;
    unsigned long x25;
    unsigned long x26;
    unsigned long x27;
    unsigned long x28;
    unsigned long x29;
    unsigned long x30;
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
    bool override_syscall_number;
};

// /usr/include/aarch64-linux-gnu/asm/ptrace.h
#pragma pack(push, 1)
struct PtraceFPRegsStruct
{
    bool dirty; // true if the debugging script has modified the state of the registers
    bool fresh; // true if the registers have already been fetched for this state
    unsigned char bool_padding[6];
    std::array<Reg128, 32> vregs;
    unsigned int fpsr;
    unsigned int fpcr;
    unsigned long padding;
};
#pragma pack(pop)

void init_libdebug_ptrace_registers(nanobind::module_ &);
