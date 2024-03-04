#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import platform

from cffi import FFI

if platform.machine() in ["i386", "x86_64"]:
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
else:
    raise NotImplementedError(f"Architecture {platform.machine()} not available.")


ffibuilder = FFI()
ffibuilder.cdef(
    user_regs_struct
    + """
    struct ptrace_hit_bp {
        int pid;
        uint64_t addr;
        uint64_t bp_instruction;
        uint64_t prev_instruction;
    };

    struct software_breakpoint {
        uint64_t addr;
        uint64_t instruction;
        uint64_t patched_instruction;
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

    int ptrace_trace_me(void);
    int ptrace_attach(int pid);
    int ptrace_detach(int pid);
    void ptrace_set_options(int pid);

    uint64_t ptrace_peekdata(int pid, uint64_t addr);
    uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data);

    uint64_t ptrace_peekuser(int pid, uint64_t addr);
    uint64_t ptrace_pokeuser(int pid, uint64_t addr, uint64_t data);

    uint64_t ptrace_geteventmsg(int pid);

    int singlestep(int tid);

    int cont_all_and_set_bps(int pid);

    struct thread_status *wait_all_and_update_regs(int pid);
    void free_thread_status_list(struct thread_status *head);

    struct user_regs_struct* register_thread(int tid);
    void unregister_thread(int tid);
    void free_thread_list();

    void register_breakpoint(int pid, uint64_t address);
    void unregister_breakpoint(uint64_t address);
    void disable_breakpoint(int pid, uint64_t address);
    void free_breakpoints();
"""
)

ffibuilder.set_source(
    "libdebug.cffi._ptrace_cffi",
    breakpoint_define
    + """
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>

struct ptrace_hit_bp {
    int pid;
    uint64_t addr;
    uint64_t bp_instruction;
    uint64_t prev_instruction;
};

struct software_breakpoint {
    uint64_t addr;
    uint64_t instruction;
    uint64_t patched_instruction;
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

struct thread *t_HEAD = NULL;

struct software_breakpoint *b_HEAD = NULL;

struct user_regs_struct* register_thread(int tid)
{
    // Verify if the thread is already registered
    struct thread *t = t_HEAD;
    while (t != NULL) {
        if (t->tid == tid)
            return &t->regs;
        t = t->next;
    }

    t = malloc(sizeof(struct thread));
    t->tid = tid;

    ptrace(PTRACE_GETREGS, tid, NULL, &t->regs);

    t->next = t_HEAD;
    t_HEAD = t;

    return &t->regs;
}

void unregister_thread(int tid)
{
    struct thread *t = t_HEAD;
    struct thread *prev = NULL;

    while (t != NULL) {
        if (t->tid == tid) {
            if (prev == NULL) {
                t_HEAD = t->next;
            } else {
                prev->next = t->next;
            }
            free(t);
            return;
        }
        prev = t;
        t = t->next;
    }
}

void free_thread_list()
{
    struct thread *t = t_HEAD;
    struct thread *next;

    while (t != NULL) {
        next = t->next;
        free(t);
        t = next;
    }

    t_HEAD = NULL;
}

int ptrace_trace_me(void)
{
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

int ptrace_attach(int pid)
{
    return ptrace(PTRACE_ATTACH, pid, NULL, NULL);
}

int ptrace_detach(int pid)
{
    return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

void ptrace_set_options(int pid)
{
    // int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

    int options = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
}

uint64_t ptrace_peekdata(int pid, uint64_t addr)
{
    // Since the value returned by a successful PTRACE_PEEK*
    // request may be -1, the caller must clear errno before the call,
    errno = 0;

    return ptrace(PTRACE_PEEKDATA, pid, (void*) addr, NULL);
}

uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data)
{
    return ptrace(PTRACE_POKEDATA, pid, (void*) addr, data);
}

uint64_t ptrace_peekuser(int pid, uint64_t addr)
{
    // Since the value returned by a successful PTRACE_PEEK*
    // request may be -1, the caller must clear errno before the call,
    errno = 0;

    return ptrace(PTRACE_PEEKUSER, pid, addr, NULL);
}

uint64_t ptrace_pokeuser(int pid, uint64_t addr, uint64_t data)
{
    return ptrace(PTRACE_POKEUSER, pid, addr, data);
}

uint64_t ptrace_geteventmsg(int pid)
{
    uint64_t data = 0;

    ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);

    return data;
}


int singlestep(int tid)
{
    // flush any register changes
    struct thread *t = t_HEAD;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs))
            perror("ptrace_setregs");
        t = t->next;
    }

    return ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL);
}

int cont_all_and_set_bps(int pid)
{
    int status = 0;

    // flush any register changes
    struct thread *t = t_HEAD;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs))
            perror("ptrace_setregs");
        t = t->next;
    }

    // iterate over all the threads and check if any of them has hit a software breakpoint
    t = t_HEAD;
    struct software_breakpoint *b;
    int t_hit;
    
    while (t != NULL) {
        t_hit = 0;
        uint64_t ip = INSTRUCTION_POINTER(t->regs);

        b = b_HEAD;
        while (b != NULL && !t_hit) {
            if (b->addr == ip)
                t_hit = 1;

            b = b->next;
        }
        

        if (t_hit) {
            // step over the breakpoint
            if (ptrace(PTRACE_SINGLESTEP, t->tid, NULL, SIGCONT))
                return -1;

            // wait for the child
            waitpid(t->tid, &status, 0);

            // status == 4991 ==> (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
            // this should happen only if threads are involved
            if (status == 4991) {
                ptrace(PTRACE_SINGLESTEP, t->tid, NULL, SIGCONT);
                waitpid(t->tid, &status, 0);
            }
        }

        t = t->next;
    }

    // Reset any software breakpoint
    b = b_HEAD;

    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, pid, (void*) b->addr, b->patched_instruction);
        }
        b = b->next;
    }

    // continue the execution of all the threads
    t = t_HEAD;
    while (t != NULL) {
        status += ptrace(PTRACE_CONT, t->tid, NULL, NULL);
        t = t->next;
    }

    return status;
}

struct thread_status *wait_all_and_update_regs(int pid)
{
    // Allocate the head of the list
    struct thread_status *head;
    head = malloc(sizeof(struct thread_status));

    // The first element is the first status we get from polling with waitpid
    head->tid = waitpid(-1, &head->status, __WALL);

    head->next = NULL;

    if (head->tid == -1) {
        free(head);
        perror("waitpid");
        return NULL;
    }

    // If we have more than one thread, we have to check the status of the other threads too
    if (t_HEAD && t_HEAD->next) {
        // First we send a SIGSTOP to all the threads
        if (kill(pid, SIGSTOP) == -1)
            perror("kill");

        // Then we wait for all the threads which are not the thread we received the status from
        struct thread *t = t_HEAD;
        int temp_tid, temp_status;
        int orig_tid = head->tid;
        struct thread_status *ts;

        while (t) {
            if (t->tid != orig_tid) {
                // Blocking wait
                temp_tid = waitpid(t->tid, &temp_status, 0);

                // Insert the new status, and poll for more but don't block
                while (temp_tid > 0) {
                    // Allocate the next element
                    ts = malloc(sizeof(struct thread_status));
                    ts->tid = temp_tid;
                    ts->status = temp_status;
                    ts->next = head;
                    head = ts;

                    temp_tid = waitpid(t->tid, &temp_status, WNOHANG);
                };
            }
            t = t->next;
        }
    }

    // Update the registers of all the threads
    struct thread *t = t_HEAD;
    while (t) {
        ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs);
        t = t->next;
    }

    // Restore any software breakpoint
    struct software_breakpoint *b = b_HEAD;

    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, pid, (void*) b->addr, b->instruction);
        }
        b = b->next;
    }

    return head;
}

void free_thread_status_list(struct thread_status *head)
{
    struct thread_status *next;

    while (head) {
        next = head->next;
        free(head);
        head = next;
    }
}

void register_breakpoint(int pid, uint64_t address)
{
    uint64_t instruction, patched_instruction;

    instruction = ptrace(PTRACE_PEEKDATA, pid, (void*) address, NULL);

    patched_instruction = INSTALL_BREAKPOINT(instruction);

    ptrace(PTRACE_POKEDATA, pid, (void*) address, patched_instruction);

    struct software_breakpoint *b = b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 1;
            return;
        }
        b = b->next;
    }

    b = malloc(sizeof(struct software_breakpoint));
    b->addr = address;
    b->instruction = instruction;
    b->patched_instruction = patched_instruction;
    b->enabled = 1;

    b->next = b_HEAD;
    b_HEAD = b;
}

void unregister_breakpoint(uint64_t address)
{
    struct software_breakpoint *b = b_HEAD;
    struct software_breakpoint *prev = NULL;

    while (b != NULL) {
        if (b->addr == address) {
            if (prev == NULL) {
                b_HEAD = b->next;
            } else {
                prev->next = b->next;
            }
            free(b);
            return;
        }
        prev = b;
        b = b->next;
    }
}

void disable_breakpoint(int pid, uint64_t address)
{
    struct software_breakpoint *b = b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 0;
            ptrace(PTRACE_POKEDATA, pid, b->addr, b->patched_instruction);
            return;
        }
        b = b->next;
    }
}

void free_breakpoints()
{
    struct software_breakpoint *b = b_HEAD;
    struct software_breakpoint *next;

    while (b != NULL) {
        next = b->next;
        free(b);
        b = next;
    }

    b_HEAD = NULL;
}
""",
    libraries=[],
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
