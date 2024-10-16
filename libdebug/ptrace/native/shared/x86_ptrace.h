//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include "libdebug_ptrace_base.h"

#define BREAKPOINT_SIZE 1
#define IS_SW_BREAKPOINT(instruction) ((instruction & 0xff) == 0xCC)

#define DR_BASE offsetof(struct user, u_debugreg[0])
#define DR_SIZE sizeof(unsigned long)
#define CTRL_LOCAL(x) (1 << (2 * x))
#define CTRL_COND(x) (16 + (4 * x))
#define CTRL_COND_VAL(x) (x == 'x' ? 0 : (x == 'w' ? 1 : 3))
#define CTRL_LEN(x) (18 + (4 * x))
#define CTRL_LEN_VAL(x) (x == 1 ? 0 : (x == 2 ? 1 : (x == 8 ? 2 : 3)))

#define IS_RET_INSTRUCTION(instruction) ((instruction & 0xff) == 0xC3 || (instruction & 0xff) == 0xCB || (instruction & 0xff) == 0xC2 || (instruction & 0xff) == 0xCA)

int IS_CALL_INSTRUCTION(uint8_t* instr);
