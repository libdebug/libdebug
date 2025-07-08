//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/stl/vector.h>
#include <nanobind/stl/list.h>
#include <nanobind/stl/map.h>
#include <nanobind/stl/pair.h>
#include <nanobind/stl/array.h>
#include <nanobind/stl/shared_ptr.h>

// Forward declare the register structs
struct PtraceRegsStruct;
struct PtraceFPRegsStruct;

struct Reg80
{
    std::array<unsigned char, 10> bytes;
};

struct Reg128
{
    std::array<unsigned char, 16> bytes;
};

struct Reg256
{
    std::array<unsigned char, 32> bytes;
};

struct Reg512
{
    std::array<unsigned char, 64> bytes;
};

struct SoftwareBreakpoint
{
    unsigned long addr;
    unsigned long instruction;
    unsigned long patched_instruction;
    bool enabled;
};

struct HardwareBreakpoint
{
    unsigned long addr;
    int tid;
    bool enabled;
    int type;
    int len;
};

struct RegisterBackup
{
    std::shared_ptr<PtraceRegsStruct> regs;
    std::shared_ptr<PtraceFPRegsStruct> fpregs;
};

struct Thread
{
    pid_t tid;
    std::map<unsigned long, HardwareBreakpoint> hardware_breakpoints;
    std::shared_ptr<PtraceRegsStruct> regs;
    std::shared_ptr<PtraceFPRegsStruct> fpregs;
    int signal_to_forward;
    RegisterBackup regs_backup;
};

struct ThreadStatus
{
    pid_t tid;
    int status;
};
