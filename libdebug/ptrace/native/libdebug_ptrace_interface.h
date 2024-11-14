//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include "libdebug_ptrace_base.h"

class LibdebugPtraceInterface
{

private:
    pid_t process_id, group_id;
    bool handle_syscall;
    std::map<pid_t, Thread> threads, dead_threads;
    std::map<unsigned long, SoftwareBreakpoint> software_breakpoints;

    // Register private methods
    int getregs(Thread &);
    int setregs(Thread &);
    void arch_getfpregs(Thread &);
    void arch_setfpregs(Thread &);
    void getfpregs(Thread &);
    void setfpregs(Thread &);
    void check_and_set_fpregs(Thread &);
    Thread &get_thread(const pid_t);

    // Control flow private methods
    void step_thread(Thread &,  bool forward_signal = true, bool step_over_hardware_bp = false);
    void cont_thread(Thread &);
    void prepare_thread(Thread &);
    void prepare_thread_for_run(Thread &);
    void prepare_process_for_run();

    // Hardware breakpoint private methods
    void install_hardware_breakpoint(const HardwareBreakpoint &);
    void remove_hardware_breakpoint(const HardwareBreakpoint &);
    unsigned long hit_hardware_breakpoint_address(const pid_t);

    // On some architectures, you are not allowed to step or cont over a hardware breakpoint
    // This method checks if the thread is on a hardware breakpoint and steps over it
    void arch_check_if_hit_and_step_over(Thread &);

    // Others
    bool check_if_dl_trampoline(unsigned long);

public:
    LibdebugPtraceInterface();

    // Debugger utility methods
    void cleanup();

    // Thread management methods
    std::pair<std::shared_ptr<PtraceRegsStruct>, std::shared_ptr<PtraceFPRegsStruct>> register_thread(const pid_t);
    void unregister_thread(const pid_t);

    // Debugger process methods
    int attach(const pid_t);
    void detach_for_migration();
    void detach_and_cont();
    void detach_for_kill();
    void set_tracing_options();

    // Debugger control flow methods
    void cont_process_and_set_bps(const bool);
    void cont_thread_and_set_bps(pid_t, const bool);
    void step(const pid_t);
    void step_until(const pid_t, const unsigned long, const int);
    std::pair<pid_t, int> stepping_finish_thread(const pid_t, const bool);

    // Debugger status and signal methods
    std::vector<std::pair<pid_t, int>> wait_thread_and_update_regs(pid_t);
    std::vector<std::pair<pid_t, int>> wait_process_and_update_regs();
    unsigned long get_thread_event_msg(const pid_t);
    void forward_signals(const std::vector<std::pair<pid_t, int>>);

    // Debugger software breakpoint methods
    void register_breakpoint(const unsigned long);
    void unregister_breakpoint(const unsigned long);
    void enable_breakpoint(const unsigned long);
    void disable_breakpoint(const unsigned long);

    // Debugger hardware breakpoint methods
    void register_hw_breakpoint(const pid_t, unsigned long address, const int type, const int len);
    void unregister_hw_breakpoint(const pid_t, const unsigned long);
    unsigned long get_hit_hw_breakpoint(const pid_t);
    int get_remaining_hw_breakpoint_count(const pid_t);
    int get_remaining_hw_watchpoint_count(const pid_t);

    // Debugger register and memory methods
    void get_fp_regs(const pid_t);
    unsigned long peek_data(const unsigned long);
    void poke_data(const unsigned long, const unsigned long);

};
