//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

#include "amd64/amd64_ptrace.h"
#include "x86_fpregs_xsave_layout.h"
#include "libdebug_ptrace_interface.h"
#include "shared/x86_ptrace.h"

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

void LibdebugPtraceInterface::step_thread(Thread &t, bool forward_signal, bool step_over_hardware_bp)
{
    // on x86, step overrides hardware breakpoints, so we do not care about them
    if (forward_signal) {
        if (ptrace(PTRACE_SINGLESTEP, t.tid, NULL, t.signal_to_forward) == -1) {
            throw std::runtime_error("ptrace singlestep failed");
        }

        t.signal_to_forward = 0;
    } else {
        if (ptrace(PTRACE_SINGLESTEP, t.tid, NULL, 0) == -1) {
            throw std::runtime_error("ptrace singlestep failed");
        }
    }
}

void LibdebugPtraceInterface::arch_check_if_hit_and_step_over()
{
    // on x86, we do not need to check for hardware breakpoints
}

int LibdebugPtraceInterface::get_remaining_hw_breakpoint_count(const pid_t tid)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (ptrace(PTRACE_PEEKUSER, tid, DR_BASE + (i * DR_SIZE), NULL) == 0) {
            break;
        }
    }

    return 4 - i;
}

int LibdebugPtraceInterface::get_remaining_hw_watchpoint_count(const pid_t tid)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (ptrace(PTRACE_PEEKUSER, tid, DR_BASE + (i * DR_SIZE), NULL) == 0) {
            break;
        }
    }

    return 4 - i;
}

int LibdebugPtraceInterface::getregs(Thread &t)
{
    return ptrace(PTRACE_GETREGS, t.tid, NULL, t.regs.get());
}

int LibdebugPtraceInterface::setregs(Thread &t)
{
    return ptrace(PTRACE_SETREGS, t.tid, NULL, t.regs.get());
}

void LibdebugPtraceInterface::arch_getfpregs(Thread &t)
{
#if HAS_XSAVE
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, padding0);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, padding0);

    if (ptrace(PTRACE_GETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
        throw std::runtime_error("ptrace getregset xstate failed");
    }
#else
    if (ptrace(PTRACE_GETFPREGS, t.tid, NULL, t.fpregs.get()) == -1) {
        throw std::runtime_error("ptrace getfpregs failed");
    }
#endif
}

void LibdebugPtraceInterface::arch_setfpregs(Thread &t)
{
#if HAS_XSAVE
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, padding0);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, padding0);

    if (ptrace(PTRACE_SETREGSET, t.tid, NT_X86_XSTATE, &iov) == -1) {
        throw std::runtime_error("ptrace setregset xstate failed");
    }
#else
    if (ptrace(PTRACE_SETFPREGS, t.tid, NULL, t.fpregs.get()) == -1) {
        throw std::runtime_error("ptrace setfpregs failed");
    }
#endif
}

void LibdebugPtraceInterface::install_hardware_breakpoint(const HardwareBreakpoint &bp)
{
    // find a free debug register
    int i;
    for (i = 0; i < 4; i++) {
        unsigned long address = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + i * DR_SIZE);

        if (!address)
            break;
    }

    if (i == 4) {
        throw std::runtime_error("No free hardware breakpoint register");
    }

    unsigned long ctrl = CTRL_LOCAL(i) | CTRL_COND_VAL(bp.type) << CTRL_COND(i) | CTRL_LEN_VAL(bp.len) << CTRL_LEN(i);

    // read the state from DR7
    unsigned long state = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + 7 * DR_SIZE);

    // reset the state, for good measure
    state &= ~(3 << CTRL_COND(i));
    state &= ~(3 << CTRL_LEN(i));

    // register the breakpoint
    state |= ctrl;

    // write the address and the state
    ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + i * DR_SIZE, bp.addr);
    ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + 7 * DR_SIZE, state);
}

void LibdebugPtraceInterface::remove_hardware_breakpoint(const HardwareBreakpoint &bp)
{
    // find the register
    int i;
    for (i = 0; i < 4; i++) {
        unsigned long address = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + i * DR_SIZE);

        if (address == bp.addr)
            break;
    }

    if (i == 4) {
        throw std::runtime_error("Breakpoint not found");
    }

    // read the state from DR7
    unsigned long state = ptrace(PTRACE_PEEKUSER, bp.tid, DR_BASE + 7 * DR_SIZE);

    // reset the state
    state &= ~(3 << CTRL_COND(i));
    state &= ~(3 << CTRL_LEN(i));

    // write the state
    ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + 7 * DR_SIZE, state);

    // reset the address
    ptrace(PTRACE_POKEUSER, bp.tid, DR_BASE + i * DR_SIZE, 0);
}

unsigned long LibdebugPtraceInterface::hit_hardware_breakpoint_address(const pid_t tid)
{
    unsigned long dr6 = ptrace(PTRACE_PEEKUSER, tid, DR_BASE + 6 * DR_SIZE);

    int index;
    for (index = 0; index < 4; index++) {
        if (dr6 & (1 << index))
            break;
    }

    if (index == 4) {
        return 0;
    }

    unsigned long address = ptrace(PTRACE_PEEKUSER, tid, DR_BASE + index * DR_SIZE);

    return address;
}

bool LibdebugPtraceInterface::check_if_dl_trampoline(unsigned long instruction_pointer)
{
    // https://codebrowser.dev/glibc/glibc/sysdeps/i386/dl-trampoline.S.html
    //      0xf7fdaf80 <_dl_runtime_resolve+16>: pop    edx
    //      0xf7fdaf81 <_dl_runtime_resolve+17>: mov    ecx,DWORD PTR [esp]
    //      0xf7fdaf84 <_dl_runtime_resolve+20>: mov    DWORD PTR [esp],eax
    //      0xf7fdaf87 <_dl_runtime_resolve+23>: mov    eax,DWORD PTR [esp+0x4]
    // =>   0xf7fdaf8b <_dl_runtime_resolve+27>: ret    0xc
    //      0xf7fdaf8e:  xchg   ax,ax
    //      0xf7fdaf90 <_dl_runtime_profile>:    push   esp
    //      0xf7fdaf91 <_dl_runtime_profile+1>:  add    DWORD PTR [esp],0x8
    //      0xf7fdaf95 <_dl_runtime_profile+5>:  push   ebp
    //      0xf7fdaf96 <_dl_runtime_profile+6>:  push   eax
    //      0xf7fdaf97 <_dl_runtime_profile+7>:  push   ecx
    //      0xf7fdaf98 <_dl_runtime_profile+8>:  push   edx

    // https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/i386/dl-trampoline.S
    //      0xf7fd9004 <_dl_runtime_resolve+20>:	pop    edx
    //      0xf7fd9005 <_dl_runtime_resolve+21>:	mov    ecx,DWORD PTR [esp]
    //      0xf7fd9008 <_dl_runtime_resolve+24>:	mov    DWORD PTR [esp],eax
    //      0xf7fd900b <_dl_runtime_resolve+27>:	mov    eax,DWORD PTR [esp+0x4]
    // =>   0xf7fd900f <_dl_runtime_resolve+31>:	ret    0xc
    //      0xf7fd9012:	lea    esi,[esi+eiz*1+0x0]
    //      0xf7fd9019:	lea    esi,[esi+eiz*1+0x0]
    //      0xf7fd9020 <_dl_runtime_resolve_shstk>:	endbr32
    //      0xf7fd9024 <_dl_runtime_resolve_shstk+4>:	push   eax
    //      0xf7fd9025 <_dl_runtime_resolve_shstk+5>:	push   edx

    unsigned long data;

    // if ((instruction_pointer & 0xf) != 0xb) {
    //     return 0;
    // }
    // breaks if libc is compiled with CET

    instruction_pointer -= 0xb;

    data = peek_data(instruction_pointer);
    data = data & 0xFFFFFFFF; // on i386 we get 4 bytes from the ptrace call, while on amd64 we get 8 bytes

    if (data != 0x240c8b5a) {
        return false;
    }

    instruction_pointer += 0x4;

    data = peek_data(instruction_pointer);
    data = data & 0xFFFFFFFF;

    if (data != 0x8b240489) {
        return false;
    }

    instruction_pointer += 0x4;

    data = peek_data(instruction_pointer);
    data = data & 0xFFFFFFFF;

    if (data != 0xc2042444) {
        return false;
    }

    instruction_pointer += 0x4;

    data = peek_data(instruction_pointer);
    data = data & 0xFFFF;

    if (data != 0x000c) {
        return false;
    }

    return true;
}
