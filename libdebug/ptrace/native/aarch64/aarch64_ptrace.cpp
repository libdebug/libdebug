//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "libdebug_ptrace_interface.h"
#include "aarch64_ptrace.h"

#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace nb = nanobind;

extern "C"
{

struct user_hwdebug_state {
    unsigned int dbg_info;
	unsigned int pad;
	struct {
		unsigned long addr;
		unsigned int ctrl;
		unsigned int pad;
	} dbg_regs[16];
};

};

static int get_breakpoint_type(const int type)
{
    if ((type & 0xff) == 'r') {
        if (((type >> 8) & 0xff) == 'w') {
            return 3;
        } else {
            return 1;
        }
    } else if ((type & 0xff) == 'w') {
        return 2;
    } else if ((type & 0xff) == 'x') {
        return 0;
    } else {
        return -1;
    }
}

int IS_CALL_INSTRUCTION(uint8_t* instr)
{
    // Check for direct CALL (BL)
    if ((instr[3] & 0xFC) == 0x94) {
        return 1; // It's a CALL
    }

    // Check for indirect CALL (BLR)
    if ((instr[3] == 0xD6 && (instr[2] & 0x3F) == 0x3F)) {
        return 1; // It's a CALL
    }

    return 0; // Not a CALL
}

static int _get_remaining_count(const int tid, const int command)
{
    struct user_hwdebug_state dbg_state = {};

    struct iovec iov;
    iov.iov_base = &dbg_state;
    iov.iov_len = sizeof dbg_state;

    ptrace(PTRACE_GETREGSET, tid, command, &iov);

    return dbg_state.dbg_info & 0xff;
}

static void _step_thread(Thread &t, bool forward_signal)
{
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

void LibdebugPtraceInterface::step_thread(Thread &t, bool forward_signal, bool step_over_hardware_bp)
{
    // on aarch64, step doesn't override hardware breakpoints
    if (step_over_hardware_bp) {
        // check if the thread is on a hardware breakpoint
        for (auto &bp : t.hardware_breakpoints) {
            if (bp.second.enabled && hit_hardware_breakpoint_address(t.tid) == bp.first) {
                // remove the breakpoint
                remove_hardware_breakpoint(bp.second);

                _step_thread(t, forward_signal);

                // re-add the breakpoint
                install_hardware_breakpoint(bp.second);

                return;
            }
        }
    }

    // either step_over_hardware_bp is false or the thread is not on a hardware breakpoint
    _step_thread(t, forward_signal);
}

void LibdebugPtraceInterface::arch_check_if_hit_and_step_over()
{
    // iterate over all the threads and check if any of them has hit a hardware breakpoint
    for (auto &t : threads) {
        unsigned long address = hit_hardware_breakpoint_address(t.second.tid);

        if (!address) {
            continue;
        }

        for (auto &bp: t.second.hardware_breakpoints) {
            if (bp.second.enabled && address == bp.first) {
                // remove the breakpoint
                remove_hardware_breakpoint(bp.second);

                // step the thread
                _step_thread(t.second, false);

                int status;
                waitpid(t.first, &status, 0);

                // status == 4991 ==> (WIFSTOPPED(status) && WSTOPSIG(status) ==
                // SIGSTOP) this should happen only if threads are involved
                if (status == 4991) {
                    step_thread(t.second, false);
                    waitpid(t.first, &status, 0);
                }

                // re-add the breakpoint
                install_hardware_breakpoint(bp.second);

                break;
            }
        }
    }
}

int LibdebugPtraceInterface::get_remaining_hw_breakpoint_count(const pid_t tid)
{
    return _get_remaining_count(tid, NT_ARM_HW_BREAK);
}

int LibdebugPtraceInterface::get_remaining_hw_watchpoint_count(const pid_t tid)
{
    return _get_remaining_count(tid, NT_ARM_HW_WATCH);
}

int LibdebugPtraceInterface::getregs(Thread &t)
{
    t.regs->override_syscall_number = 0;

    struct iovec iov;
    iov.iov_base = t.regs.get();
    iov.iov_len = sizeof(PtraceRegsStruct);

    return ptrace(PTRACE_GETREGSET, t.tid, NT_PRSTATUS, &iov);
}

int LibdebugPtraceInterface::setregs(Thread &t)
{
    struct iovec iov;

    if (t.regs->override_syscall_number) {
        iov.iov_base = &(t.regs->x8);
        iov.iov_len = sizeof(t.regs->x8);
        ptrace(PTRACE_SETREGSET, t.tid, NT_ARM_SYSTEM_CALL, &iov);
        t.regs->override_syscall_number = 0;
    }

    iov.iov_base = t.regs.get();
    iov.iov_len = sizeof(PtraceRegsStruct);

    return ptrace(PTRACE_SETREGSET, t.tid, NT_PRSTATUS, &iov);
}

void LibdebugPtraceInterface::arch_getfpregs(Thread &t)
{
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, vregs);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, vregs);

    if (ptrace(PTRACE_GETREGSET, t.tid, NT_FPREGSET, &iov) == -1) {
        throw std::runtime_error("ptrace getregset fpregset failed");
    }
}

void LibdebugPtraceInterface::arch_setfpregs(Thread &t)
{
    iovec iov;
    PtraceFPRegsStruct *fpregs = t.fpregs.get();

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(PtraceFPRegsStruct, vregs);
    iov.iov_len = sizeof(PtraceFPRegsStruct) - offsetof(PtraceFPRegsStruct, vregs);

    if (ptrace(PTRACE_SETREGSET, t.tid, NT_FPREGSET, &iov) == -1) {
        throw std::runtime_error("ptrace setregset fpregset failed");
    }
}

void LibdebugPtraceInterface::install_hardware_breakpoint(const HardwareBreakpoint &bp)
{
    // find a free debug register
    struct user_hwdebug_state state = {};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = sizeof state;

    unsigned long command = get_breakpoint_type(bp.type) == 0 ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    ptrace(PTRACE_GETREGSET, bp.tid, command, &iov);

    int i;
    for (i = 0; i < 16; i++) {
        if (!state.dbg_regs[i].addr)
            break;
    }

    if (i == 16) {
        throw std::runtime_error("No debug registers available");
    }

    int len = bp.len;
    if ((bp.type & 0xff) == 'x') {
        // Hardware breakpoint can only be of length 4
        len = 4;
    }

    unsigned int length = (1 << len) - 1;
    unsigned int condition = get_breakpoint_type(bp.type);
    unsigned int control = (length << 5) | (condition << 3) | (2 << 1) | 1;

    state.dbg_regs[i].addr = bp.addr;
    state.dbg_regs[i].ctrl = control;

    ptrace(PTRACE_SETREGSET, bp.tid, command, &iov);
}

void LibdebugPtraceInterface::remove_hardware_breakpoint(const HardwareBreakpoint &bp)
{
    struct user_hwdebug_state state = {};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = sizeof state;

    unsigned long command = get_breakpoint_type(bp.type) == 0 ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    ptrace(PTRACE_GETREGSET, bp.tid, command, &iov);

    int i;
    for (i = 0; i < 16; i++) {
        if (state.dbg_regs[i].addr == bp.addr)
            break;
    }

    if (i == 16) {
        throw std::runtime_error("Breakpoint not found");
    }

    state.dbg_regs[i].addr = 0;
    state.dbg_regs[i].ctrl = 0;

    ptrace(PTRACE_SETREGSET, bp.tid, command, &iov);
}

unsigned long LibdebugPtraceInterface::hit_hardware_breakpoint_address(const pid_t tid)
{
    siginfo_t si;

    if (ptrace(PTRACE_GETSIGINFO, tid, NULL, &si) == -1) {
        return 0;
    }

    // Check that the signal is a SIGTRAP and the code is 0x4
    if (!(si.si_signo == SIGTRAP && si.si_code == 0x4)) {
        return 0;
    }

    return (unsigned long) si.si_addr;
}

bool LibdebugPtraceInterface::check_if_dl_trampoline(unsigned long instruction_pointer)
{
    (void) instruction_pointer;

    // Does not apply to AArch64
    return false;
}

void init_libdebug_ptrace_registers(nb::module_ &m) {
    nb::class_<PtraceRegsStruct>(m, "PtraceRegsStruct")
        .def_rw("x0", &PtraceRegsStruct::x0)
        .def_rw("x1", &PtraceRegsStruct::x1)
        .def_rw("x2", &PtraceRegsStruct::x2)
        .def_rw("x3", &PtraceRegsStruct::x3)
        .def_rw("x4", &PtraceRegsStruct::x4)
        .def_rw("x5", &PtraceRegsStruct::x5)
        .def_rw("x6", &PtraceRegsStruct::x6)
        .def_rw("x7", &PtraceRegsStruct::x7)
        .def_rw("x8", &PtraceRegsStruct::x8)
        .def_rw("x9", &PtraceRegsStruct::x9)
        .def_rw("x10", &PtraceRegsStruct::x10)
        .def_rw("x11", &PtraceRegsStruct::x11)
        .def_rw("x12", &PtraceRegsStruct::x12)
        .def_rw("x13", &PtraceRegsStruct::x13)
        .def_rw("x14", &PtraceRegsStruct::x14)
        .def_rw("x15", &PtraceRegsStruct::x15)
        .def_rw("x16", &PtraceRegsStruct::x16)
        .def_rw("x17", &PtraceRegsStruct::x17)
        .def_rw("x18", &PtraceRegsStruct::x18)
        .def_rw("x19", &PtraceRegsStruct::x19)
        .def_rw("x20", &PtraceRegsStruct::x20)
        .def_rw("x21", &PtraceRegsStruct::x21)
        .def_rw("x22", &PtraceRegsStruct::x22)
        .def_rw("x23", &PtraceRegsStruct::x23)
        .def_rw("x24", &PtraceRegsStruct::x24)
        .def_rw("x25", &PtraceRegsStruct::x25)
        .def_rw("x26", &PtraceRegsStruct::x26)
        .def_rw("x27", &PtraceRegsStruct::x27)
        .def_rw("x28", &PtraceRegsStruct::x28)
        .def_rw("x29", &PtraceRegsStruct::x29)
        .def_rw("x30", &PtraceRegsStruct::x30)
        .def_rw("sp", &PtraceRegsStruct::sp)
        .def_rw("pc", &PtraceRegsStruct::pc)
        .def_rw("pstate", &PtraceRegsStruct::pstate)
        .def_rw("override_syscall_number", &PtraceRegsStruct::override_syscall_number);

    nb::class_<PtraceFPRegsStruct>(m, "PtraceFPRegsStruct")
        .def_prop_rw("dirty", &PtraceFPRegsStruct::is_dirty, &PtraceFPRegsStruct::set_dirty)
        .def_prop_rw("fresh", &PtraceFPRegsStruct::is_fresh, &PtraceFPRegsStruct::set_fresh)
        .def_ro("vregs", &PtraceFPRegsStruct::vregs)
        .def_rw("fpsr", &PtraceFPRegsStruct::fpsr)
        .def_rw("fpcr", &PtraceFPRegsStruct::fpcr);
}
