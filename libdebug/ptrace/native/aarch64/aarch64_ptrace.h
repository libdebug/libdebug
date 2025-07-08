//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "libdebug_ptrace_base.h"
#include "fp_regs_definition.h"

#define INSTRUCTION_POINTER(regs) (regs->pc)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFF00000000) | 0xD4200000)
#define BREAKPOINT_SIZE 4
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xD4200000)

#define IS_RET_INSTRUCTION(instruction) (instruction == 0xD65F03C0)

#define SET_SYSCALL_NUMBER(regs, value) regs->x8 = value

#define SET_SYSCALL_ARG0(regs, value) regs->x0 = value
#define SET_SYSCALL_ARG1(regs, value) regs->x1 = value
#define SET_SYSCALL_ARG2(regs, value) regs->x2 = value
#define SET_SYSCALL_ARG3(regs, value) regs->x3 = value
#define SET_SYSCALL_ARG4(regs, value) regs->x4 = value
#define SET_SYSCALL_ARG5(regs, value) regs->x5 = value
#define SET_SYSCALL_ARG6(regs, value) regs->x6 = value

#define GET_SYSCALL_RESULT(regs) regs->x0

#define SYSCALL_INSTRUCTION 0xD4000001

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

    PtraceFPRegsStruct(PtraceFPRegsStructDefinition unused)
        : dirty(false), fresh(false), bool_padding{0}, fpsr(0), fpcr(0), padding(0)
    {
        // Initialize vregs to zero
        for (auto &vreg : vregs) {
            vreg.bytes.fill(0);
        }

        (void) unused; // Avoid unused parameter warning
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
};
#pragma pack(pop)

void init_libdebug_ptrace_registers(nanobind::module_ &);
