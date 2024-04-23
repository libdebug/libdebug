//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

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

struct global_state {
    struct thread *t_HEAD;
    struct software_breakpoint *b_HEAD;
    _Bool syscall_hooks_enabled;
};

struct user_regs_struct *register_thread(struct global_state *state, int tid)
{
    // Verify if the thread is already registered
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (t->tid == tid) return &t->regs;
        t = t->next;
    }

    t = malloc(sizeof(struct thread));
    t->tid = tid;

    ptrace(PTRACE_GETREGS, tid, NULL, &t->regs);

    t->next = state->t_HEAD;
    state->t_HEAD = t;

    return &t->regs;
}

void unregister_thread(struct global_state *state, int tid)
{
    struct thread *t = state->t_HEAD;
    struct thread *prev = NULL;

    while (t != NULL) {
        if (t->tid == tid) {
            if (prev == NULL) {
                state->t_HEAD = t->next;
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

void free_thread_list(struct global_state *state)
{
    struct thread *t = state->t_HEAD;
    struct thread *next;

    while (t != NULL) {
        next = t->next;
        free(t);
        t = next;
    }

    state->t_HEAD = NULL;
}

int ptrace_trace_me(void)
{
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

int ptrace_attach(int pid)
{
    return ptrace(PTRACE_ATTACH, pid, NULL, NULL);
}

void ptrace_detach_all(struct global_state *state, int pid)
{
    struct thread *t = state->t_HEAD;
    // note that the order is important: the main thread must be detached last
    while (t != NULL) {
        // let's attempt to read the registers of the thread
        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs)) {
            // if we can't read the registers, the thread is probably still running
            // ensure that the thread is stopped
            tgkill(pid, t->tid, SIGSTOP);

            // wait for it to stop
            waitpid(t->tid, NULL, 0);
        }

        // detach from it
        if (ptrace(PTRACE_DETACH, t->tid, NULL, NULL))
            fprintf(stderr, "ptrace_detach failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        // kill it
        tgkill(pid, t->tid, SIGKILL);

        t = t->next;
    }

    waitpid(pid, NULL, 0);
}

void ptrace_detach_for_migration(struct global_state *state, int pid)
{
    struct thread *t = state->t_HEAD;
    // note that the order is important: the main thread must be detached last
    while (t != NULL) {
        // let's attempt to read the registers of the thread
        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs)) {
            // if we can't read the registers, the thread is probably still running
            // ensure that the thread is stopped
            tgkill(pid, t->tid, SIGSTOP);

            // wait for it to stop
            waitpid(t->tid, NULL, 0);
        }

        // detach from it
        if (ptrace(PTRACE_DETACH, t->tid, NULL, NULL))
            fprintf(stderr, "ptrace_detach failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        t = t->next;
    }
}

void ptrace_reattach_from_gdb(struct global_state *state, int pid)
{
    struct thread *t = state->t_HEAD;
    // note that the order is important: the main thread must be detached last
    while (t != NULL) {
        if (ptrace(PTRACE_ATTACH, t->tid, NULL, NULL))
            fprintf(stderr, "ptrace_attach failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs))
            fprintf(stderr, "ptrace_getregs failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        t = t->next;
    }
}

void ptrace_set_options(int pid)
{
    int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
                  PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

    ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
}

uint64_t ptrace_peekdata(int pid, uint64_t addr)
{
    // Since the value returned by a successful PTRACE_PEEK*
    // request may be -1, the caller must clear errno before the call,
    errno = 0;

    return ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
}

uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data)
{
    return ptrace(PTRACE_POKEDATA, pid, (void *)addr, data);
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

int singlestep(struct global_state *state, int tid)
{
    // flush any register changes
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs))
            perror("ptrace_setregs");
        t = t->next;
    }

    return ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL);
}

int step_until(struct global_state *state, int tid, uint64_t addr, int max_steps)
{
    // flush any register changes
    struct thread *t = state->t_HEAD, *stepping_thread = NULL;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs))
            perror("ptrace_setregs");

        if (t->tid == tid)
            stepping_thread = t;

        t = t->next;
    }

    int count = 0, status = 0;
    uint64_t previous_ip;

    if (!stepping_thread) {
        perror("Thread not found");
        return -1;
    }

    while (max_steps == -1 || count < max_steps) {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) return -1;

        // wait for the child
        waitpid(tid, &status, 0);

        previous_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // update the registers
        ptrace(PTRACE_GETREGS, tid, NULL, &stepping_thread->regs);

        if (INSTRUCTION_POINTER(stepping_thread->regs) == addr) break;

        // if the instruction pointer didn't change, we have to step again
        // because we hit a hardware breakpoint
        if (INSTRUCTION_POINTER(stepping_thread->regs) == previous_ip) continue;

        count++;
    }

    return 0;
}

int cont_all_and_set_bps(struct global_state *state, int pid)
{
    int status = 0;

    // flush any register changes
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs))
            fprintf(stderr, "ptrace_setregs failed for thread %d: %s\\n",
                    t->tid, strerror(errno));
        t = t->next;
    }

    // iterate over all the threads and check if any of them has hit a software
    // breakpoint
    t = state->t_HEAD;
    struct software_breakpoint *b;
    int t_hit;

    while (t != NULL) {
        t_hit = 0;
        uint64_t ip = INSTRUCTION_POINTER(t->regs);

        b = state->b_HEAD;
        while (b != NULL && !t_hit) {
            if (b->addr == ip)
                // we hit a software breakpoint on this thread
                t_hit = 1;

            b = b->next;
        }

        if (t_hit) {
            // step over the breakpoint
            if (ptrace(PTRACE_SINGLESTEP, t->tid, NULL, NULL)) return -1;

            // wait for the child
            waitpid(t->tid, &status, 0);

            // status == 4991 ==> (WIFSTOPPED(status) && WSTOPSIG(status) ==
            // SIGSTOP) this should happen only if threads are involved
            if (status == 4991) {
                ptrace(PTRACE_SINGLESTEP, t->tid, NULL, NULL);
                waitpid(t->tid, &status, 0);
            }
        }

        t = t->next;
    }

    // Reset any software breakpoint
    b = state->b_HEAD;
    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, pid, (void *)b->addr,
                   b->patched_instruction);
        }
        b = b->next;
    }

    // continue the execution of all the threads
    t = state->t_HEAD;
    while (t != NULL) {
        if (ptrace(state->syscall_hooks_enabled ? PTRACE_SYSCALL : PTRACE_CONT, t->tid, NULL, NULL))
            fprintf(stderr, "ptrace_cont failed for thread %d: %s\\n", t->tid,
                    strerror(errno));
        t = t->next;
    }

    return status;
}

struct thread_status *wait_all_and_update_regs(struct global_state *state, int pid)
{
    // Allocate the head of the list
    struct thread_status *head;
    head = malloc(sizeof(struct thread_status));
    head->next = NULL;

    // The first element is the first status we get from polling with waitpid
    head->tid = waitpid(-getpgid(pid), &head->status, 0);

    if (head->tid == -1) {
        free(head);
        perror("waitpid");
        return NULL;
    }

    // We must interrupt all the other threads with a SIGSTOP
    struct thread *t = state->t_HEAD;
    int temp_tid, temp_status;
    while (t != NULL) {
        if (t->tid != head->tid) {
            // If GETREGS succeeds, the thread is already stopped, so we must
            // not "stop" it again
            if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs) == -1) {
                // Stop the thread with a SIGSTOP
                tgkill(pid, t->tid, SIGSTOP);
                // Wait for the thread to stop
                temp_tid = waitpid(t->tid, &temp_status, 0);

                // Register the status of the thread, as it might contain useful
                // information
                struct thread_status *ts = malloc(sizeof(struct thread_status));
                ts->tid = temp_tid;
                ts->status = temp_status;
                ts->next = head;
                head = ts;
            }
        }
        t = t->next;
    }

    // We keep polling but don't block, we want to get all the statuses we can
    while ((temp_tid = waitpid(-getpgid(pid), &temp_status, WNOHANG)) > 0) {
        struct thread_status *ts = malloc(sizeof(struct thread_status));
        ts->tid = temp_tid;
        ts->status = temp_status;
        ts->next = head;
        head = ts;
    }

    // Update the registers of all the threads
    t = state->t_HEAD;
    while (t) {
        ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs);
        t = t->next;
    }

    // Restore any software breakpoint
    struct software_breakpoint *b = state->b_HEAD;

    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, pid, (void *)b->addr, b->instruction);
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

void register_breakpoint(struct global_state *state, int pid, uint64_t address)
{
    uint64_t instruction, patched_instruction;

    instruction = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);

    patched_instruction = INSTALL_BREAKPOINT(instruction);

    ptrace(PTRACE_POKEDATA, pid, (void *)address, patched_instruction);

    struct software_breakpoint *b = state->b_HEAD;

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

    // Breakpoints should be inserted ordered by address, increasing
    // This is important, because we don't want a breakpoint patching another
    if (state->b_HEAD == NULL || state->b_HEAD->addr > address) {
        b->next = state->b_HEAD;
        state->b_HEAD = b;
        return;
    } else {
        struct software_breakpoint *prev = state->b_HEAD;
        struct software_breakpoint *next = state->b_HEAD->next;

        while (next != NULL && next->addr < address) {
            prev = next;
            next = next->next;
        }

        b->next = next;
        prev->next = b;
    }
}

void unregister_breakpoint(struct global_state *state, uint64_t address)
{
    struct software_breakpoint *b = state->b_HEAD;
    struct software_breakpoint *prev = NULL;

    while (b != NULL) {
        if (b->addr == address) {
            if (prev == NULL) {
                state->b_HEAD = b->next;
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

void enable_breakpoint(struct global_state *state, uint64_t address)
{
    struct software_breakpoint *b = state->b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 1;
        }
        b = b->next;
    }
}

void disable_breakpoint(struct global_state *state, uint64_t address)
{
    struct software_breakpoint *b = state->b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 0;
        }
        b = b->next;
    }
}

void free_breakpoints(struct global_state *state)
{
    struct software_breakpoint *b = state->b_HEAD;
    struct software_breakpoint *next;

    while (b != NULL) {
        next = b->next;
        free(b);
        b = next;
    }

    state->b_HEAD = NULL;
}
