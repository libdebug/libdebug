#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import platform

from cffi import FFI

if platform.machine() == "x86_64":
    user_regs_struct = """
    struct user_regs_struct
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
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.rip)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
    #define BREAKPOINT_SIZE 1
    """
elif platform.machine() == "i686":
    user_regs_struct = """
    struct user_regs_struct
    {
        unsigned long ebx;
        unsigned long ecx;
        unsigned long edx;
        unsigned long esi;
        unsigned long edi;
        unsigned long ebp;
        unsigned long eax;
        unsigned long xds;
        unsigned long xes;
        unsigned long xfs;
        unsigned long xgs;
        unsigned long orig_eax;
        unsigned long eip;
        unsigned long xcs;
        unsigned long eflags;
        unsigned long esp;
        unsigned long xss;
    };
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.eip)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFF00) | 0xCC)
    #define BREAKPOINT_SIZE 1
    """
elif platform.machine() == "aarch64":
    user_regs_struct = """
    struct user_regs_struct
    {
        unsigned long r0;
        unsigned long r1;
        unsigned long r2;
        unsigned long r3;
        unsigned long r4;
        unsigned long r5;
        unsigned long r6;
        unsigned long r7;
        unsigned long r8;
        unsigned long r9;
        unsigned long r10;
        unsigned long r11;
        unsigned long r12;
        unsigned long r13;
        unsigned long r14;
        unsigned long r15;
        unsigned long r16;
        unsigned long r17;
        unsigned long r18;
        unsigned long r19;
        unsigned long r20;
        unsigned long r21;
        unsigned long r22;
        unsigned long r23;
        unsigned long r24;
        unsigned long r25;
        unsigned long r26;
        unsigned long r27;
        unsigned long r28;
        unsigned long r29;
        unsigned long r30;
        unsigned long sp;
        unsigned long pc;
        unsigned long pstate;
    };
    """

    breakpoint_define = """
    #define INSTRUCTION_POINTER(regs) (regs.pc)
    #define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFF00000000) | 0xD4200000)
    #define BREAKPOINT_SIZE 4
    """
else:
    raise NotImplementedError(f"Architecture {platform.machine()} not available.")


ffibuilder = FFI()
ffibuilder.cdef(
    user_regs_struct
    + """
    struct ptrace_hit_bp {
        int pid;
        unsigned long addr;
        unsigned long bp_instruction;
        unsigned long prev_instruction;
    };

    struct software_breakpoint {
        unsigned long addr;
        unsigned long instruction;
        unsigned long patched_instruction;
        char enabled;
        struct software_breakpoint *next;
    };

    struct thread {
        int tid;
        struct user_regs_struct regs;
        struct thread *next;
    };

    struct thread_status {
        int tid;
        int status;
        struct thread_status *next;
    };

    struct global_state {
        struct thread *t_HEAD;
        struct software_breakpoint *b_HEAD;
        _Bool syscall_hooks_enabled;
    };


    int ptrace_trace_me(void);
    int ptrace_attach(int pid);
    void ptrace_detach_all(struct global_state *state, int pid);
    void ptrace_detach_for_migration(struct global_state *state, int pid);
    void ptrace_reattach_from_gdb(struct global_state *state, int pid);
    void ptrace_set_options(int pid);

    unsigned long ptrace_peekdata(int pid, unsigned long addr);
    unsigned long ptrace_pokedata(int pid, unsigned long addr, unsigned long data);

    unsigned long ptrace_peekuser(int pid, unsigned long addr);
    unsigned long ptrace_pokeuser(int pid, unsigned long addr, unsigned long data);

    unsigned long ptrace_geteventmsg(int pid);

    int singlestep(struct global_state *state, int tid);
    int step_until(struct global_state *state, int tid, unsigned long addr, int max_steps);

    int cont_all_and_set_bps(struct global_state *state, int pid);

    struct thread_status *wait_all_and_update_regs(struct global_state *state, int pid);
    void free_thread_status_list(struct thread_status *head);

    struct user_regs_struct* register_thread(struct global_state *state, int tid);
    void unregister_thread(struct global_state *state, int tid);
    void free_thread_list(struct global_state *state);

    void register_breakpoint(struct global_state *state, int pid, unsigned long address);
    void unregister_breakpoint(struct global_state *state, unsigned long address);
    void enable_breakpoint(struct global_state *state, unsigned long address);
    void disable_breakpoint(struct global_state *state, unsigned long address);
    void free_breakpoints(struct global_state *state);
"""
)

with open("libdebug/cffi/ptrace_cffi_source.c") as f:
    ffibuilder.set_source(
        "libdebug.cffi._ptrace_cffi",
        breakpoint_define + f.read(),
        libraries=[],
    )

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
