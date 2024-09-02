//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

// Run some static assertions to ensure that the fp types are correct
#ifdef ARCH_AMD64
    #ifndef FPREGS_AVX
        #error "FPREGS_AVX must be defined"
    #endif

    #ifndef XSAVE
        #error "XSAVE must be defined"
    #endif

    #if (FPREGS_AVX == 0)
        _Static_assert((sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, padding0)) == 512, "user_fpregs_struct size is not 512 bytes");
    #elif (FPREGS_AVX == 1)
        _Static_assert((sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, padding0)) == 896, "user_fpregs_struct size is not 896 bytes");
    #elif (FPREGS_AVX == 2)
        _Static_assert((sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, padding0)) == 2696, "user_fpregs_struct size is not 2696 bytes");
    #else
        #error "FPREGS_AVX must be 0, 1 or 2"
    #endif
#endif

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

struct hardware_breakpoint {
    uint64_t addr;
    int tid;
    char enabled;
    char type[2];
    char len;
    struct hardware_breakpoint *next;
};

struct thread {
    int tid;
    struct ptrace_regs_struct regs;
    struct fp_regs_struct fpregs;
    int signal_to_forward;
    struct thread *next;
};

struct thread_status {
    int tid;
    int status;
    struct thread_status *next;
};

struct global_state {
    struct thread *t_HEAD;
    struct thread *dead_t_HEAD;
    struct software_breakpoint *sw_b_HEAD;
    struct hardware_breakpoint *hw_b_HEAD;
    _Bool handle_syscall_enabled;
};

#ifdef ARCH_AMD64
int getregs(int tid, struct ptrace_regs_struct *regs)
{
    return ptrace(PTRACE_GETREGS, tid, NULL, regs);
}

int setregs(int tid, struct ptrace_regs_struct *regs)
{
    return ptrace(PTRACE_SETREGS, tid, NULL, regs);
}
#endif

#ifdef ARCH_AARCH64
int getregs(int tid, struct ptrace_regs_struct *regs)
{
    regs->override_syscall_number = 0;

    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(struct ptrace_regs_struct);
    return ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov);
}

int setregs(int tid, struct ptrace_regs_struct *regs)
{
    struct iovec iov;

    if (regs->override_syscall_number) {
        iov.iov_base = &regs->x8;
        iov.iov_len = sizeof(regs->x8);
        ptrace(PTRACE_SETREGSET, tid, NT_ARM_SYSTEM_CALL, &iov);
        regs->override_syscall_number = 0;
    }

    iov.iov_base = regs;
    iov.iov_len = sizeof(struct ptrace_regs_struct);
    return ptrace(PTRACE_SETREGSET, tid, NT_PRSTATUS, &iov);
}
#endif

#ifdef ARCH_AMD64

#define DR_BASE 0x350
#define DR_SIZE 0x8
#define CTRL_LOCAL(x) (1 << (2 * x))
#define CTRL_COND(x) (16 + (4 * x))
#define CTRL_COND_VAL(x) (x == 'x' ? 0 : (x == 'w' ? 1 : 3))
#define CTRL_LEN(x) (18 + (4 * x))
#define CTRL_LEN_VAL(x) (x == 1 ? 0 : (x == 2 ? 1 : (x == 8 ? 2 : 3)))

void install_hardware_breakpoint(struct hardware_breakpoint *bp)
{
    // find a free debug register
    int i;
    for (i = 0; i < 4; i++) {
        unsigned long address = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + i * DR_SIZE);

        if (!address)
            break;
    }

    if (i == 4) {
        perror("No debug registers available");
        return;
    }

    unsigned long ctrl = CTRL_LOCAL(i) | CTRL_COND_VAL(bp->type[0]) << CTRL_COND(i) | CTRL_LEN_VAL(bp->len) << CTRL_LEN(i);

    // read the state from DR7
    unsigned long state = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + 7 * DR_SIZE);

    // reset the state, for good measure
    state &= ~(3 << CTRL_COND(i));
    state &= ~(3 << CTRL_LEN(i));

    // register the breakpoint
    state |= ctrl;

    // write the address and the state
    ptrace(PTRACE_POKEUSER, bp->tid, DR_BASE + i * DR_SIZE, bp->addr);
    ptrace(PTRACE_POKEUSER, bp->tid, DR_BASE + 7 * DR_SIZE, state);
}


void remove_hardware_breakpoint(struct hardware_breakpoint *bp)
{
    // find the register
    int i;
    for (i = 0; i < 4; i++) {
        unsigned long address = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + i * DR_SIZE);

        if (address == bp->addr)
            break;
    }

    if (i == 4) {
        perror("Breakpoint not found");
        return;
    }

    // read the state from DR7
    unsigned long state = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + 7 * DR_SIZE);

    // reset the state
    state &= ~(3 << CTRL_COND(i));
    state &= ~(3 << CTRL_LEN(i));

    // write the state
    ptrace(PTRACE_POKEUSER, bp->tid, DR_BASE + 7 * DR_SIZE, state);

    // clear the address
    ptrace(PTRACE_POKEUSER, bp->tid, DR_BASE + i * DR_SIZE, 0);
}

int is_breakpoint_hit(struct hardware_breakpoint *bp)
{
    unsigned long status = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + 6 * DR_SIZE);

    int index;
    if (status & 0x1)
        index = 0;
    else if (status & 0x2)
        index = 1;
    else if (status & 0x4)
        index = 2;
    else if (status & 0x8)
        index = 3;
    else
        return 0;

    unsigned long address = ptrace(PTRACE_PEEKUSER, bp->tid, DR_BASE + index * DR_SIZE);

    if (address == bp->addr)
        return 1;

    return 0;
}

int get_remaining_hw_breakpoint_count(struct global_state *state, int tid)
{
    int i;
    for (i = 0; i < 4; i++) {
        unsigned long address = ptrace(PTRACE_PEEKUSER, tid, DR_BASE + i * DR_SIZE);

        if (!address)
            break;
    }

    return 4 - i;
}

int get_remaining_hw_watchpoint_count(struct global_state *state, int tid)
{
    return get_remaining_hw_breakpoint_count(state, tid);
}
#endif

#ifdef ARCH_AARCH64
struct user_hwdebug_state {
    unsigned int dbg_info;
	unsigned int pad;
	struct {
		unsigned long addr;
		unsigned int ctrl;
		unsigned int pad;
	} dbg_regs[16];
};

int get_breakpoint_type(char type[2])
{
    if (type[0] == 'r') {
        if (type[1] == 'w') {
            return 3;
        } else {
            return 1;
        }
    } else if (type[0] == 'w') {
        return 2;
    } else if (type[0] == 'x') {
        return 0;
    } else {
        return -1;
    }
}

void install_hardware_breakpoint(struct hardware_breakpoint *bp)
{
    // find a free debug register
    struct user_hwdebug_state state = {0};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = sizeof state;

    unsigned long command = get_breakpoint_type(bp->type) == 0 ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    ptrace(PTRACE_GETREGSET, bp->tid, command, &iov);

    int i;
    for (i = 0; i < 16; i++) {
        if (!state.dbg_regs[i].addr)
            break;
    }

    if (i == 16) {
        perror("No debug registers available");
        return;
    }

    if (bp->type[0] == 'x') {
        // Hardware breakpoint can only be of length 4
        bp->len = 4;
    }

    unsigned int length = (1 << bp->len) - 1;
    unsigned int condition = get_breakpoint_type(bp->type);
    unsigned int control = (length << 5) | (condition << 3) | (2 << 1) | 1;

    state.dbg_regs[i].addr = bp->addr;
    state.dbg_regs[i].ctrl = control;

    ptrace(PTRACE_SETREGSET, bp->tid, command, &iov);
}

void remove_hardware_breakpoint(struct hardware_breakpoint *bp)
{
    struct user_hwdebug_state state = {0};

    struct iovec iov;
    iov.iov_base = &state;
    iov.iov_len = sizeof state;

    unsigned long command = get_breakpoint_type(bp->type) == 0 ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH;

    ptrace(PTRACE_GETREGSET, bp->tid, command, &iov);

    int i;
    for (i = 0; i < 16; i++) {
        if (state.dbg_regs[i].addr == bp->addr)
            break;
    }

    if (i == 16) {
        perror("Breakpoint not found");
        return;
    }

    state.dbg_regs[i].addr = 0;
    state.dbg_regs[i].ctrl = 0;

    ptrace(PTRACE_SETREGSET, bp->tid, command, &iov);
}

int is_breakpoint_hit(struct hardware_breakpoint *bp)
{
    siginfo_t si;

    if (ptrace(PTRACE_GETSIGINFO, bp->tid, NULL, &si) == -1) {
        return 0;
    }

    // Check that the signal is a SIGTRAP and the code is 0x4
    if (!(si.si_signo == SIGTRAP && si.si_code == 0x4)) {
        return 0;
    }
    
    unsigned long addr = (unsigned long) si.si_addr;

    if (addr == bp->addr) {
        return 1;
    }

    return 0;
}

int _get_remaining_count(struct global_state *state, int tid, int command)
{
    struct user_hwdebug_state dbg_state = {0};

    struct iovec iov;
    iov.iov_base = &dbg_state;
    iov.iov_len = sizeof dbg_state;

    ptrace(PTRACE_GETREGSET, tid, command, &iov);

    return dbg_state.dbg_info & 0xff;
}

int get_remaining_hw_breakpoint_count(struct global_state *state, int tid)
{
    return _get_remaining_count(state, tid, NT_ARM_HW_BREAK);
}

int get_remaining_hw_watchpoint_count(struct global_state *state, int tid)
{
    return _get_remaining_count(state, tid, NT_ARM_HW_WATCH);
}
#endif

struct thread *get_thread(struct global_state *state, int tid)
{
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (t->tid == tid) return t;
        t = t->next;
    }

    return NULL;
}

struct fp_regs_struct *get_thread_fp_regs(struct global_state *state, int tid)
{
    struct thread *t = get_thread(state, tid);

    if (t) {
        return &t->fpregs;
    }

    return NULL;
}

#ifdef ARCH_AMD64
void get_fp_regs(int tid, struct fp_regs_struct *fpregs)
{
    #if (XSAVE == 0)

    #else
        struct iovec iov;

        iov.iov_base = (unsigned char *)(fpregs) + offsetof(struct fp_regs_struct, padding0);
        iov.iov_len = sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, padding0);

        if (ptrace(PTRACE_GETREGSET, tid, NT_X86_XSTATE, &iov) == -1) {
            perror("ptrace_getregset_xstate");
        }
    #endif

    fpregs->fresh = 1;
}

void set_fp_regs(int tid, struct fp_regs_struct *fpregs)
{
    #if (XSAVE == 0)

    #else
        struct iovec iov;

        iov.iov_base = (unsigned char *)(fpregs) + offsetof(struct fp_regs_struct, padding0);
        iov.iov_len = sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, padding0);

        if (ptrace(PTRACE_SETREGSET, tid, NT_X86_XSTATE, &iov) == -1) {
            perror("ptrace_setregset_xstate");
        }
    #endif

    fpregs->dirty = 0;
    fpregs->fresh = 0;
}
#endif

#ifdef ARCH_AARCH64
void get_fp_regs(int tid, struct fp_regs_struct *fpregs)
{
    struct iovec iov;

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(struct fp_regs_struct, vregs);
    iov.iov_len = sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, vregs);

    if (ptrace(PTRACE_GETREGSET, tid, NT_FPREGSET, &iov) == -1) {
        perror("ptrace_getregset_xstate");
    }

    fpregs->fresh = 1;
}

void set_fp_regs(int tid, struct fp_regs_struct *fpregs)
{
    struct iovec iov;

    iov.iov_base = (unsigned char *)(fpregs) + offsetof(struct fp_regs_struct, vregs);
    iov.iov_len = sizeof(struct fp_regs_struct) - offsetof(struct fp_regs_struct, vregs);

    if (ptrace(PTRACE_SETREGSET, tid, NT_FPREGSET, &iov) == -1) {
        perror("ptrace_setregset_xstate");
    }

    fpregs->dirty = 0;
    fpregs->fresh = 0;
}
#endif

void check_and_set_fp_regs(struct thread *t)
{
    if (t->fpregs.dirty) {
        set_fp_regs(t->tid, &t->fpregs);
    }
}

struct ptrace_regs_struct *register_thread(struct global_state *state, int tid)
{
    // Verify if the thread is already registered
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (t->tid == tid) return &t->regs;
        t = t->next;
    }

    t = malloc(sizeof(struct thread));
    t->tid = tid;
    t->signal_to_forward = 0;

#ifdef ARCH_AMD64
    t->fpregs.type = FPREGS_AVX;
#endif
    t->fpregs.dirty = 0;
    t->fpregs.fresh = 0;

    getregs(tid, &t->regs);

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
            // Add the thread to the dead list
            t->next = state->dead_t_HEAD;
            state->dead_t_HEAD = t;
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

    t = state->dead_t_HEAD;

    while (t != NULL) {
        next = t->next;
        free(t);
        t = next;
    }

    state->dead_t_HEAD = NULL;
}

int ptrace_trace_me(void)
{
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

int ptrace_attach(int pid)
{
    return ptrace(PTRACE_ATTACH, pid, NULL, NULL);
}

void ptrace_detach_for_kill(struct global_state *state, int pid)
{
    struct thread *t = state->t_HEAD;
    // note that the order is important: the main thread must be detached last
    while (t != NULL) {
        // let's attempt to read the registers of the thread
        if (getregs(t->tid, &t->regs)) {
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
        // the user might have modified the state of the registers
        // so we use SETREGS to check if the process is running
        if (setregs(t->tid, &t->regs)) {
            // if we can't read the registers, the thread is probably still running
            // ensure that the thread is stopped
            tgkill(pid, t->tid, SIGSTOP);

            // wait for it to stop
            waitpid(t->tid, NULL, 0);

            // set the registers again, as the first time it failed
            setregs(t->tid, &t->regs);
            check_and_set_fp_regs(t);
        }

        // Be sure that the thread will not run during gdb reattachment
        tgkill(pid, t->tid, SIGSTOP);

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

        if (getregs(t->tid, &t->regs))
            fprintf(stderr, "ptrace_getregs failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        t = t->next;
    }
}

void ptrace_detach_and_cont(struct global_state *state, int pid)
{
    ptrace_detach_for_migration(state, pid);

    // continue the execution of the process
    kill(pid, SIGCONT);
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

uint64_t ptrace_geteventmsg(int pid)
{
    uint64_t data = 0;

    ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);

    return data;
}

long singlestep(struct global_state *state, int tid)
{
    // flush any register changes
    struct thread *t = state->t_HEAD;
    int signal_to_forward = 0;
    while (t != NULL) {
        if (setregs(t->tid, &t->regs))
            perror("ptrace_setregs");

        check_and_set_fp_regs(t);

        if (t->tid == tid) {
            signal_to_forward = t->signal_to_forward;
            t->signal_to_forward = 0;
        }
        t = t->next;
    }

#ifdef ARCH_AMD64
    return ptrace(PTRACE_SINGLESTEP, tid, NULL, signal_to_forward);
#endif

#ifdef ARCH_AARCH64
    // Cannot singlestep if we are stopped on a hardware breakpoint
    // So we have to check for this, remove it, singlestep and then re-add it
    struct hardware_breakpoint *bp = state->hw_b_HEAD;

    while (bp != NULL) {
        if (bp->tid == tid && bp->enabled && is_breakpoint_hit(bp)) {
            remove_hardware_breakpoint(bp);
            long ret = ptrace(PTRACE_SINGLESTEP, tid, NULL, signal_to_forward);
            install_hardware_breakpoint(bp);
            return ret;
        }
        bp = bp->next;
    }

    return ptrace(PTRACE_SINGLESTEP, tid, NULL, signal_to_forward);
#endif
}

int step_until(struct global_state *state, int tid, uint64_t addr, int max_steps)
{
    // flush any register changes
    struct thread *t = state->t_HEAD, *stepping_thread = NULL;
    while (t != NULL) {
        if (setregs(t->tid, &t->regs))
            perror("ptrace_setregs");

        check_and_set_fp_regs(t);

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

    // remove any hardware breakpoint that might be set on the stepping thread
    struct hardware_breakpoint *bp = state->hw_b_HEAD;

    while (bp != NULL) {
        if (bp->tid == tid && bp->enabled) {
            remove_hardware_breakpoint(bp);
        }
        bp = bp->next;
    }

    while (max_steps == -1 || count < max_steps) {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) return -1;

        // wait for the child
        waitpid(tid, &status, 0);

        previous_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // update the registers
        getregs(tid, &stepping_thread->regs);

        if (INSTRUCTION_POINTER(stepping_thread->regs) == addr) break;

        // if the instruction pointer didn't change, we have to step again
        // because we hit a hardware breakpoint
        if (INSTRUCTION_POINTER(stepping_thread->regs) == previous_ip) continue;

        count++;
    }

    // re-add the hardware breakpoints
    bp = state->hw_b_HEAD;

    while (bp != NULL) {
        if (bp->tid == tid && bp->enabled) {
            install_hardware_breakpoint(bp);
        }
        bp = bp->next;
    }

    return 0;
}

int prepare_for_run(struct global_state *state, int pid)
{
    int status = 0;

    // flush any register changes
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (setregs(t->tid, &t->regs))
            fprintf(stderr, "ptrace_setregs failed for thread %d: %s\\n",
                    t->tid, strerror(errno));

        check_and_set_fp_regs(t);

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

        b = state->sw_b_HEAD;
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

#ifdef ARCH_AARCH64
    // iterate over all the threads and check if any of them has hit a hardware
    // breakpoint
    t = state->t_HEAD;
    struct hardware_breakpoint *bp;
    int bp_hit;

    while (t != NULL) {
        bp_hit = 0;

        bp = state->hw_b_HEAD;
        while (bp != NULL && !bp_hit) {
            if (bp->tid == t->tid && bp->enabled && is_breakpoint_hit(bp)) {
                // we hit a hardware breakpoint on this thread
                bp_hit = 1;
                break;
            }

            bp = bp->next;
        }

        if (bp_hit) {
            // remove the breakpoint
            remove_hardware_breakpoint(bp);

            // step over the breakpoint
            if (ptrace(PTRACE_SINGLESTEP, t->tid, NULL, NULL)) return -1;

            // wait for the child
            waitpid(t->tid, &status, 0);

            // re-add the breakpoint
            install_hardware_breakpoint(bp);
        }

        t = t->next;
    }
#endif

    // Reset any software breakpoint
    b = state->sw_b_HEAD;
    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, pid, (void *)b->addr,
                   b->patched_instruction);
        }
        b = b->next;
    }

    return status;
}

int cont_all_and_set_bps(struct global_state *state, int pid)
{
    int status = prepare_for_run(state, pid);

    // continue the execution of all the threads
    struct thread *t = state->t_HEAD;
    while (t != NULL) {
        if (ptrace(state->handle_syscall_enabled
 ? PTRACE_SYSCALL : PTRACE_CONT, t->tid, NULL, t->signal_to_forward))
            fprintf(stderr, "ptrace_cont failed for thread %d with signal %d: %s\\n", t->tid, t->signal_to_forward,
                    strerror(errno));
        t->signal_to_forward = 0;
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
            if (getregs(t->tid, &t->regs) == -1) {
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
        getregs(t->tid, &t->regs);
        t = t->next;
    }

    // Restore any software breakpoint
    struct software_breakpoint *b = state->sw_b_HEAD;

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

    struct software_breakpoint *b = state->sw_b_HEAD;

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
    if (state->sw_b_HEAD == NULL || state->sw_b_HEAD->addr > address) {
        b->next = state->sw_b_HEAD;
        state->sw_b_HEAD = b;
        return;
    } else {
        struct software_breakpoint *prev = state->sw_b_HEAD;
        struct software_breakpoint *next = state->sw_b_HEAD->next;

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
    struct software_breakpoint *b = state->sw_b_HEAD;
    struct software_breakpoint *prev = NULL;

    while (b != NULL) {
        if (b->addr == address) {
            if (prev == NULL) {
                state->sw_b_HEAD = b->next;
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
    struct software_breakpoint *b = state->sw_b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 1;
            break;
        }
        b = b->next;
    }

    // Patch the instruction with the breakpoint
    if (b != NULL) {
        ptrace(PTRACE_POKEDATA, state->t_HEAD->tid, (void *)address, b->patched_instruction);
    }
}

void disable_breakpoint(struct global_state *state, uint64_t address)
{
    struct software_breakpoint *b = state->sw_b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 0;
            break;
        }
        b = b->next;
    }

    // Restore the original instruction
    if (b != NULL) {
        ptrace(PTRACE_POKEDATA, state->t_HEAD->tid, (void *)address, b->instruction);
    }
}

void free_breakpoints(struct global_state *state)
{
    struct software_breakpoint *b = state->sw_b_HEAD;
    struct software_breakpoint *next;

    while (b != NULL) {
        next = b->next;
        free(b);
        b = next;
    }

    state->sw_b_HEAD = NULL;

    struct hardware_breakpoint *h = state->hw_b_HEAD;
    struct hardware_breakpoint *next_h;

    while (h != NULL) {
        next_h = h->next;
        free(h);
        h = next_h;
    }

    state->hw_b_HEAD = NULL;
}

int stepping_finish(struct global_state *state, int tid)
{
    int status = prepare_for_run(state, tid);

    struct thread *stepping_thread = state->t_HEAD;
    while (stepping_thread != NULL) {
        if (stepping_thread->tid == tid) {
            break;
        }

        stepping_thread = stepping_thread->next;
    }

    if (!stepping_thread) {
        perror("Thread not found");
        return -1;
    }

    uint64_t previous_ip, current_ip;
    uint64_t opcode_window, opcode;

    // We need to keep track of the nested calls
    int nested_call_counter = 1;

    do {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) return -1;

        // wait for the child
        waitpid(tid, &status, 0);

        previous_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // update the registers
        getregs(tid, &stepping_thread->regs);

        current_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // Get value at current instruction pointer
        opcode_window = ptrace(PTRACE_PEEKDATA, tid, (void *)current_ip, NULL);

#ifdef ARCH_AMD64
        // on amd64 we care only about the first byte
        opcode = opcode_window & 0xFF;
#endif

#ifdef ARCH_AARCH64
        opcode = opcode_window & 0xFFFFFFFF;
#endif

        // if the instruction pointer didn't change, we return
        // because we hit a hardware breakpoint
        // we do the same if we hit a software breakpoint
        if (current_ip == previous_ip || IS_SW_BREAKPOINT(opcode))
            goto cleanup;

        // If we hit a call instruction, we increment the counter
        if (IS_CALL_INSTRUCTION((uint8_t*) &opcode_window))
            nested_call_counter++;
        else if (IS_RET_INSTRUCTION(opcode))
            nested_call_counter--;

    } while (nested_call_counter > 0);

    // We are in a return instruction, do the last step
    if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) return -1;

    // wait for the child
    waitpid(tid, &status, 0);

    // update the registers
    getregs(tid, &stepping_thread->regs);

cleanup:
    // remove any installed breakpoint
    struct software_breakpoint *b = state->sw_b_HEAD;
    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, tid, (void *)b->addr, b->instruction);
        }
        b = b->next;
    }

    return 0;
}

void register_hw_breakpoint(struct global_state *state, int tid, uint64_t address, char type[2], char len)
{
    struct hardware_breakpoint *b = state->hw_b_HEAD;

    while (b != NULL) {
        if (b->addr == address && b->tid == tid) {
            perror("Breakpoint already registered");
            return;
        }
        b = b->next;
    }

    b = malloc(sizeof(struct hardware_breakpoint));
    b->addr = address;
    b->tid = tid;
    b->enabled = 1;
    b->type[0] = type[0];
    b->type[1] = type[1];
    b->len = len;

    b->next = state->hw_b_HEAD;
    state->hw_b_HEAD = b;

    install_hardware_breakpoint(b);
}

void unregister_hw_breakpoint(struct global_state *state, int tid, uint64_t address)
{
    struct hardware_breakpoint *b = state->hw_b_HEAD;
    struct hardware_breakpoint *prev = NULL;

    while (b != NULL) {
        if (b->addr == address && b->tid == tid) {
            if (prev == NULL) {
                state->hw_b_HEAD = b->next;
            } else {
                prev->next = b->next;
            }

            if (b->enabled) {
                remove_hardware_breakpoint(b);
            }

            free(b);
            return;
        }
        prev = b;
        b = b->next;
    }
}

void enable_hw_breakpoint(struct global_state *state, int tid, uint64_t address)
{
    struct hardware_breakpoint *b = state->hw_b_HEAD;

    while (b != NULL) {
        if (b->addr == address && b->tid == tid) {
            if (!b->enabled) {
                install_hardware_breakpoint(b);
            }

            b->enabled = 1;
        }
        b = b->next;
    }
}

void disable_hw_breakpoint(struct global_state *state, int tid, uint64_t address)
{
    struct hardware_breakpoint *b = state->hw_b_HEAD;

    while (b != NULL) {
        if (b->addr == address && b->tid == tid) {
            if (b->enabled) {
                remove_hardware_breakpoint(b);
            }

            b->enabled = 0;
        }
        b = b->next;
    }
}

unsigned long get_hit_hw_breakpoint(struct global_state *state, int tid)
{
    struct hardware_breakpoint *b = state->hw_b_HEAD;

    while (b != NULL) {
        if (b->tid == tid && is_breakpoint_hit(b)) {
            return b->addr;
        }
        b = b->next;
    }

    return 0;
}
