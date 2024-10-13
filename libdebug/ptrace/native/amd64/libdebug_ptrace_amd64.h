//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>
#include <nanobind/stl/array.h>

#include "../libdebug_ptrace_base.h"

#define INSTRUCTION_POINTER(regs) (regs->rip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
#define BREAKPOINT_SIZE 1
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)

#define DR_BASE offsetof(struct user, u_debugreg[0])
#define DR_SIZE sizeof(unsigned long)
#define CTRL_LOCAL(x) (1 << (2 * x))
#define CTRL_COND(x) (16 + (4 * x))
#define CTRL_COND_VAL(x) (x == 'x' ? 0 : (x == 'w' ? 1 : 3))
#define CTRL_LEN(x) (18 + (4 * x))
#define CTRL_LEN_VAL(x) (x == 1 ? 0 : (x == 2 ? 1 : (x == 8 ? 2 : 3)))

#define IS_RET_INSTRUCTION(instruction) (instruction == 0xC3 || instruction == 0xCB || instruction == 0xC2 || instruction == 0xCA)

int IS_CALL_INSTRUCTION(uint8_t* instr);

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

#pragma pack(push, 1)
struct PtraceFPRegsStruct
{
    unsigned long type;
    bool dirty; // true if the debugging script has modified the state of the registers
    bool fresh; // true if the registers have already been fetched for this state
    unsigned char bool_padding[6];
    unsigned char padding0[32];
    std::array<Reg128, 8> mmx;
    std::array<Reg128, 16> xmm0;
    unsigned char padding1[96];
    // end of the 512 byte legacy region
    unsigned char padding2[64];
    // ymm0 starts at offset 576
    std::array<Reg128, 16> ymm0;
    unsigned char padding3[64];
    unsigned char padding4[192]; // mpx save area
};
#pragma pack(pop)

void init_libdebug_ptrace_amd64(nanobind::module_ &m);
