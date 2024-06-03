//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#define INSTRUCTION_POINTER(regs) (regs.rip)
#define INSTALL_BREAKPOINT(instruction) ((instruction & 0xFFFFFFFFFFFFFF00) | 0xCC)
#define BREAKPOINT_SIZE 1
#define IS_SW_BREAKPOINT(instruction) (instruction == 0xCC)

#define IS_RET_INSTRUCTION(instruction) (instruction == 0xC3 || instruction == 0xCB || instruction == 0xC2 || instruction == 0xCA)

// X86_64 Architecture specific
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


struct registers
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

typedef struct {
    PyObject_HEAD
    struct registers *regs;
} ThreadRegs;

PyObject* ThreadRegs_new(PyTypeObject* type, PyObject* args, PyObject* kwargs)
{
    ThreadRegs* self = (ThreadRegs*)type->tp_alloc(type, 0);
    return (PyObject*)self;
}

void ThreadRegs_dealloc(ThreadRegs* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

#define GETTER(name) \
    static PyObject* ThreadRegs_get_##name(ThreadRegs* self, void* closure) \
    { \
        return PyLong_FromUnsignedLong(self->regs->name); \
    }

#define SETTER(name) \
    static int ThreadRegs_set_##name(ThreadRegs* self, PyObject* value, void* closure) \
    { \
        if (!PyLong_Check(value)) { \
            PyErr_SetString(PyExc_TypeError, "The value must be an integer"); \
            return -1; \
        } \
        self->regs->name = PyLong_AsUnsignedLong(value); \
        return 0; \
    }

#define GETTER_SETTER(name) \
    GETTER(name) \
    SETTER(name)

GETTER_SETTER(r15)
GETTER_SETTER(r14)
GETTER_SETTER(r13)
GETTER_SETTER(r12)
GETTER_SETTER(rbp)
GETTER_SETTER(rbx)
GETTER_SETTER(r11)
GETTER_SETTER(r10)
GETTER_SETTER(r9)
GETTER_SETTER(r8)
GETTER_SETTER(rax)
GETTER_SETTER(rcx)
GETTER_SETTER(rdx)
GETTER_SETTER(rsi)
GETTER_SETTER(rdi)
GETTER_SETTER(orig_rax)
GETTER_SETTER(rip)
GETTER_SETTER(cs)
GETTER_SETTER(eflags)
GETTER_SETTER(rsp)
GETTER_SETTER(ss)
GETTER_SETTER(fs_base)
GETTER_SETTER(gs_base)
GETTER_SETTER(ds)
GETTER_SETTER(es)
GETTER_SETTER(fs)
GETTER_SETTER(gs)

PyGetSetDef ThreadRegs_getset[] =
{
    {"r15", (getter)ThreadRegs_get_r15, (setter)ThreadRegs_set_r15, "r15 register", NULL},
    {"r14", (getter)ThreadRegs_get_r14, (setter)ThreadRegs_set_r14, "r14 register", NULL},
    {"r13", (getter)ThreadRegs_get_r13, (setter)ThreadRegs_set_r13, "r13 register", NULL},
    {"r12", (getter)ThreadRegs_get_r12, (setter)ThreadRegs_set_r12, "r12 register", NULL},
    {"rbp", (getter)ThreadRegs_get_rbp, (setter)ThreadRegs_set_rbp, "rbp register", NULL},
    {"rbx", (getter)ThreadRegs_get_rbx, (setter)ThreadRegs_set_rbx, "rbx register", NULL},
    {"r11", (getter)ThreadRegs_get_r11, (setter)ThreadRegs_set_r11, "r11 register", NULL},
    {"r10", (getter)ThreadRegs_get_r10, (setter)ThreadRegs_set_r10, "r10 register", NULL},
    {"r9", (getter)ThreadRegs_get_r9, (setter)ThreadRegs_set_r9, "r9 register", NULL},
    {"r8", (getter)ThreadRegs_get_r8, (setter)ThreadRegs_set_r8, "r8 register", NULL},
    {"rax", (getter)ThreadRegs_get_rax, (setter)ThreadRegs_set_rax, "rax register", NULL},
    {"rcx", (getter)ThreadRegs_get_rcx, (setter)ThreadRegs_set_rcx, "rcx register", NULL},
    {"rdx", (getter)ThreadRegs_get_rdx, (setter)ThreadRegs_set_rdx, "rdx register", NULL},
    {"rsi", (getter)ThreadRegs_get_rsi, (setter)ThreadRegs_set_rsi, "rsi register", NULL},
    {"rdi", (getter)ThreadRegs_get_rdi, (setter)ThreadRegs_set_rdi, "rdi register", NULL},
    {"orig_rax", (getter)ThreadRegs_get_orig_rax, (setter)ThreadRegs_set_orig_rax, "orig_rax register", NULL},
    {"rip", (getter)ThreadRegs_get_rip, (setter)ThreadRegs_set_rip, "rip register", NULL},
    {"cs", (getter)ThreadRegs_get_cs, (setter)ThreadRegs_set_cs, "cs register", NULL},
    {"eflags", (getter)ThreadRegs_get_eflags, (setter)ThreadRegs_set_eflags, "eflags register", NULL},
    {"rsp", (getter)ThreadRegs_get_rsp, (setter)ThreadRegs_set_rsp, "rsp register", NULL},
    {"ss", (getter)ThreadRegs_get_ss, (setter)ThreadRegs_set_ss, "ss register", NULL},
    {"fs_base", (getter)ThreadRegs_get_fs_base, (setter)ThreadRegs_set_fs_base, "fs_base register", NULL},
    {"gs_base", (getter)ThreadRegs_get_gs_base, (setter)ThreadRegs_set_gs_base, "gs_base register", NULL},
    {"ds", (getter)ThreadRegs_get_ds, (setter)ThreadRegs_set_ds, "ds register", NULL},
    {"es", (getter)ThreadRegs_get_es, (setter)ThreadRegs_set_es, "es register", NULL},
    {"fs", (getter)ThreadRegs_get_fs, (setter)ThreadRegs_set_fs, "fs register", NULL},
    {"gs", (getter)ThreadRegs_get_gs, (setter)ThreadRegs_set_gs, "gs register", NULL},
    {NULL}
};

PyTypeObject ThreadRegsType =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "libptrace.ThreadRegs",
    .tp_doc = "ThreadRegs object",
    .tp_basicsize = sizeof(ThreadRegs),
    .tp_new = ThreadRegs_new,
    .tp_dealloc = (destructor)ThreadRegs_dealloc,
    .tp_getset = ThreadRegs_getset,
};

struct software_breakpoint
{
    unsigned long addr;
    unsigned long instruction;
    unsigned long patched_instruction;
    _Bool enabled;
    struct software_breakpoint *next;
};

struct thread
{
    pid_t tid;
    struct registers regs;
    int signal_to_deliver;
    struct thread *next;
};

struct thread_status {
    pid_t tid;
    int status;
    struct thread_status *next;
};

struct tracer_state
{
    pid_t pid;
    struct thread *t_HEAD;
    struct software_breakpoint *b_HEAD;
    _Bool syscall_hooks_enabled;
};

typedef struct
{
    PyObject_HEAD
    struct tracer_state state;
} Ptracer;

static PyObject* Ptracer_new(PyTypeObject* type, PyObject* args, PyObject* kwargs)
{
    Ptracer* self = (Ptracer*)type->tp_alloc(type, 0);
    return (PyObject*)self;
}

static void Ptracer_dealloc(Ptracer* self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* Ptracer_attach(Ptracer* self, PyObject* args)
{
    pid_t pid;
    if (!PyArg_ParseTuple(args, "i", &pid)) {
        return NULL;
    }
    self->state.pid = pid;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return Py_None;
}

static PyObject* Ptracer_setpid(Ptracer* self, PyObject* args)
{
    pid_t pid;
    if (!PyArg_ParseTuple(args, "i", &pid)) {
        return NULL;
    }
    self->state.pid = pid;
    return Py_None;
}

static PyObject* Ptracer_register_thread(Ptracer* self, PyObject* args)
{
    pid_t tid;
    if (!PyArg_ParseTuple(args, "i", &tid)) {
        return NULL;
    }

    // Verify if the thread is already registered
    struct thread *t = self->state.t_HEAD;
    while (t != NULL) {
        if (t->tid == tid) {
            PyErr_SetString(PyExc_ValueError, "Thread already registered");
            return NULL;
        }
        t = t->next;
    }

    // Create a new thread
    struct thread *new_thread = malloc(sizeof(struct thread));
    new_thread->tid = tid;
    new_thread->signal_to_deliver = 0;

    // Get the registers of the new thread
    ptrace(PTRACE_GETREGS, tid, NULL, &new_thread->regs);

    // Add the new thread to the list
    new_thread->next = self->state.t_HEAD;
    self->state.t_HEAD = new_thread;

    // Return the ThreadRegs object
    ThreadRegs* regs = (ThreadRegs*)ThreadRegs_new(&ThreadRegsType, NULL, NULL);
    regs->regs = &new_thread->regs;

    Py_INCREF(regs);

    return (PyObject*)regs;
}

static PyObject* Ptracer_unregister_thread(Ptracer* self, PyObject* args)
{
    pid_t tid;
    if (!PyArg_ParseTuple(args, "i", &tid)) {
        return NULL;
    }

    // Verify if the thread is registered
    struct thread *t = self->state.t_HEAD;
    struct thread *prev = NULL;
    while (t != NULL) {
        if (t->tid == tid) {
            if (prev == NULL) {
                self->state.t_HEAD = t->next;
            } else {
                prev->next = t->next;
            }
            free(t);
            return Py_None;
        }
        prev = t;
        t = t->next;
    }

    PyErr_SetString(PyExc_ValueError, "Thread not registered");
    return NULL;
}

static PyObject* Ptracer_free_thread_list(Ptracer* self)
{
    struct thread *t = self->state.t_HEAD;
    while (t != NULL) {
        struct thread *next = t->next;
        free(t);
        t = next;
    }
    self->state.t_HEAD = NULL;
    return Py_None;
}

static PyObject* Ptracer_free_breakpoint_list(Ptracer* self)
{
    struct software_breakpoint *b = self->state.b_HEAD;
    while (b != NULL) {
        struct software_breakpoint *next = b->next;
        free(b);
        b = next;
    }
    self->state.b_HEAD = NULL;
    return Py_None;
}

static PyObject* Ptracer_detach_for_kill(Ptracer* self)
{
    struct thread *t = self->state.t_HEAD;

    // Note that the order is important here
    while (t != NULL) {
        // Let's attempt to read the registers of the thread
        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &t->regs) == -1) {
            // If we can't read the registers, it's probably still running
            tgkill(self->state.pid, t->tid, SIGSTOP);

            // Wait for the thread to stop
            waitpid(t->tid, NULL, 0);
        }

        // Detach the thread
        if (ptrace(PTRACE_DETACH, t->tid, NULL, NULL) == -1) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        // Kill it
        tgkill(self->state.pid, t->tid, SIGKILL);

        t = t->next;
    }

    // Wait again for the zombie process
    waitpid(self->state.pid, NULL, 0);

    return Py_None;
}

static PyObject* Ptracer_set_options(Ptracer* self)
{
    int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
                PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;

    ptrace(PTRACE_SETOPTIONS, self->state.pid, NULL, options);

    return Py_None;
}

static PyObject* Ptracer_peek_data(Ptracer* self, PyObject *arg)
{
    unsigned long addr;
    if (!PyArg_ParseTuple(arg, "K", &addr)) {
        return NULL;
    }

    errno = 0;

    long data = ptrace(PTRACE_PEEKDATA, self->state.pid, addr, NULL);

    if (errno) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyLong_FromUnsignedLong(data);
}

static PyObject* Ptracer_poke_data(Ptracer* self, PyObject *args)
{
    unsigned long addr;
    unsigned long data;
    if (!PyArg_ParseTuple(args, "KK", &addr, &data)) {
        return NULL;
    }

    errno = 0;

    if (ptrace(PTRACE_POKEDATA, self->state.pid, addr, data) == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return Py_None;
}

static PyObject* Ptracer_peek_user(Ptracer* self, PyObject *args)
{
    pid_t tid;
    unsigned long addr;
    if (!PyArg_ParseTuple(args, "iK", &tid, &addr)) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");
        return NULL;
    }

    errno = 0;

    long data = ptrace(PTRACE_PEEKUSER, tid, addr, NULL);

    if (errno) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyLong_FromUnsignedLong(data);
}

static PyObject* Ptracer_poke_user(Ptracer* self, PyObject *args)
{
    pid_t tid;
    unsigned long addr;
    unsigned long data;
    if (!PyArg_ParseTuple(args, "iKK", &tid, &addr, &data)) {
        PyErr_SetString(PyExc_TypeError, "Invalid arguments");
        return NULL;
    }

    errno = 0;

    if (ptrace(PTRACE_POKEUSER, tid, addr, data) == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyLong_FromUnsignedLong(0);
}

static PyObject* Ptracer_get_event_msg(Ptracer* self, PyObject *arg)
{
    pid_t tid;
    if (!PyArg_ParseTuple(arg, "i", &tid)) {
        return NULL;
    }

    long data = 0;

    ptrace(PTRACE_GETEVENTMSG, tid, NULL, &data);

    return PyLong_FromUnsignedLong(data);
}

static PyObject* Ptracer_singlestep(Ptracer* self, PyObject *arg)
{
    pid_t tid;
    if (!PyArg_ParseTuple(arg, "i", &tid)) {
        return NULL;
    }

    // Flush any register changes
    struct thread *t = self->state.t_HEAD;
    int signal_to_deliver = 0;
    while (t != NULL) {
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs) == -1) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        if (t->tid == tid) {
            signal_to_deliver = t->signal_to_deliver;
            t->signal_to_deliver = 0;
        }

        t = t->next;
    }

    ptrace(PTRACE_SINGLESTEP, tid, NULL, signal_to_deliver);

    return Py_None;
}

static PyObject* Ptracer_deliver_signal_to_thread(Ptracer* self, PyObject *args)
{
    pid_t tid;
    int signal;
    if (!PyArg_ParseTuple(args, "ii", &tid, &signal)) {
        return NULL;
    }

    struct thread *t = self->state.t_HEAD;
    while (t != NULL) {
        if (t->tid == tid) {
            t->signal_to_deliver = signal;
            return Py_None;
        }
        t = t->next;
    }

    PyErr_SetString(PyExc_ValueError, "Thread not registered");
    return NULL;
}

int prepare_for_run(struct tracer_state *state, int pid)
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

    return status;
}

static PyObject* Ptracer_cont_all_and_set_bps(Ptracer *self, PyObject *const *args, Py_ssize_t nargs)
{
    _Bool syscall_hooks_enabled;

    if (nargs == 1) {
        syscall_hooks_enabled = PyObject_IsTrue(args[0]);
    } else {
        PyErr_SetString(PyExc_TypeError, "cont_all_and_set_bps() takes exactly 1 argument");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS

    int status = prepare_for_run(&self->state, self->state.pid);

    if (status == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    // continue all threads
    struct thread *t = self->state.t_HEAD;
    while (t != NULL) {
        if (ptrace(syscall_hooks_enabled ? PTRACE_SYSCALL : PTRACE_CONT, t->tid, NULL, t->signal_to_deliver) == -1) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        t->signal_to_deliver = 0;
        t = t->next;
    }

    Py_END_ALLOW_THREADS

    return Py_None;
}

static PyObject* Ptracer_wait_all_and_update_regs(Ptracer* self)
{
    struct tracer_state *state = &self->state;
    pid_t pid = state->pid;

    struct thread_status *head;

    Py_BEGIN_ALLOW_THREADS

    // Allocate the head of the list
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

    Py_END_ALLOW_THREADS

    // Create a list of tuples with the thread id and the status
    PyObject *statuses = PyList_New(0);
    struct thread_status *ts = head, *next;
    while (ts != NULL) {
        PyObject *status = Py_BuildValue("ii", ts->tid, ts->status);
        PyList_Append(statuses, status);
        next = ts->next;
        free(ts);
        ts = next;
    }

    return statuses;
}

static PyObject* Ptracer_register_breakpoint(Ptracer* self, PyObject *arg)
{
    unsigned long address;
    if (!PyArg_ParseTuple(arg, "K", &address)) {
        return NULL;
    }

    pid_t pid = self->state.pid;

    unsigned long instruction, patched_instruction;

    instruction = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);

    patched_instruction = INSTALL_BREAKPOINT(instruction);

    ptrace(PTRACE_POKEDATA, pid, (void *)address, patched_instruction);

    struct software_breakpoint *b = self->state.b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 1;
            return Py_None;
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
    if (self->state.b_HEAD == NULL || self->state.b_HEAD->addr > address) {
        b->next = self->state.b_HEAD;
        self->state.b_HEAD = b;
    } else {
        struct software_breakpoint *prev = self->state.b_HEAD;
        struct software_breakpoint *next = self->state.b_HEAD->next;

        while (next != NULL && next->addr < address) {
            prev = next;
            next = next->next;
        }

        b->next = next;
        prev->next = b;
    }

    return Py_None;
}

static PyObject* Ptracer_unregister_breakpoint(Ptracer* self, PyObject *arg)
{
    unsigned long address;
    if (!PyArg_ParseTuple(arg, "K", &address)) {
        return NULL;
    }

    struct software_breakpoint *b = self->state.b_HEAD;
    struct software_breakpoint *prev = NULL;

    while (b != NULL) {
        if (b->addr == address) {
            if (prev == NULL) {
                self->state.b_HEAD = b->next;
            } else {
                prev->next = b->next;
            }

            free(b);
            return Py_None;
        }

        prev = b;
        b = b->next;
    }

    PyErr_SetString(PyExc_ValueError, "Breakpoint not registered");
    return NULL;
}

static PyObject* enable_breakpoint(Ptracer* self, PyObject *arg)
{
    unsigned long address;
    if (!PyArg_ParseTuple(arg, "K", &address)) {
        return NULL;
    }

    struct software_breakpoint *b = self->state.b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 1;
            return Py_None;
        }

        b = b->next;
    }

    PyErr_SetString(PyExc_ValueError, "Breakpoint not registered");
    return NULL;
}

static PyObject* disable_breakpoint(Ptracer* self, PyObject *arg)
{
    unsigned long address;
    if (!PyArg_ParseTuple(arg, "K", &address)) {
        return NULL;
    }

    struct software_breakpoint *b = self->state.b_HEAD;

    while (b != NULL) {
        if (b->addr == address) {
            b->enabled = 0;
            return Py_None;
        }

        b = b->next;
    }

    PyErr_SetString(PyExc_ValueError, "Breakpoint not registered");
    return NULL;
}

static PyObject* Ptracer_step_until(Ptracer *self, PyObject *args)
{
    pid_t tid;
    unsigned long addr;
    int max_steps = -1;
    if (!PyArg_ParseTuple(args, "iK|i", &tid, &addr, &max_steps)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS

    struct tracer_state *state = &self->state;

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
        PyErr_SetString(PyExc_ValueError, "Thread not registered");
        return NULL;
    }

    while (max_steps == -1 || count < max_steps) {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

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

    Py_END_ALLOW_THREADS

    return Py_None;
}

void ptrace_detach_for_migration(struct tracer_state *state, pid_t pid)
{
    struct thread *t = state->t_HEAD;
    // note that the order is important: the main thread must be detached last
    while (t != NULL) {
        // the user might have modified the state of the registers
        // so we use SETREGS to check if the process is running
        if (ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs)) {
            // if we can't read the registers, the thread is probably still running
            // ensure that the thread is stopped
            tgkill(pid, t->tid, SIGSTOP);

            // wait for it to stop
            waitpid(t->tid, NULL, 0);

            // set the registers again, as the first time it failed
            ptrace(PTRACE_SETREGS, t->tid, NULL, &t->regs);
        }

        // detach from it
        if (ptrace(PTRACE_DETACH, t->tid, NULL, NULL))
            fprintf(stderr, "ptrace_detach failed for thread %d: %s\\n", t->tid,
                    strerror(errno));

        t = t->next;
    }
}

static PyObject* ptrace_detach_and_cont(Ptracer* self)
{
    pid_t pid = self->state.pid;
    struct tracer_state *state = &self->state;

    ptrace_detach_for_migration(state, pid);

    // continue the execution of the process
    kill(pid, SIGCONT);

    return Py_None;
}

static PyObject* exact_finish(Ptracer *self, PyObject *arg)
{
    pid_t tid;
    if (!PyArg_ParseTuple(arg, "i", &tid)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS

    struct tracer_state *state = &self->state;

    int status = prepare_for_run(state, tid);

    struct thread *stepping_thread = state->t_HEAD;
    while (stepping_thread != NULL) {
        if (stepping_thread->tid == tid) {
            break;
        }

        stepping_thread = stepping_thread->next;
    }

    if (!stepping_thread) {
        PyErr_SetString(PyExc_ValueError, "Thread not registered");
        return NULL;
    }

    uint64_t previous_ip, current_ip;
    uint64_t opcode_window, first_opcode_byte;

    // We need to keep track of the nested calls
    int nested_call_counter = 1;

    do {
        if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        // wait for the child
        waitpid(tid, &status, 0);

        previous_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // update the registers
        ptrace(PTRACE_GETREGS, tid, NULL, &stepping_thread->regs);

        current_ip = INSTRUCTION_POINTER(stepping_thread->regs);

        // Get value at current instruction pointer
        opcode_window = ptrace(PTRACE_PEEKDATA, tid, (void *)current_ip, NULL);
        first_opcode_byte = opcode_window & 0xFF;

        // if the instruction pointer didn't change, we return
        // because we hit a hardware breakpoint
        // we do the same if we hit a software breakpoint
        if (current_ip == previous_ip || IS_SW_BREAKPOINT(first_opcode_byte))
            goto cleanup;

        // If we hit a call instruction, we increment the counter
        if (IS_CALL_INSTRUCTION((uint8_t*) &opcode_window))
            nested_call_counter++;
        else if (IS_RET_INSTRUCTION(first_opcode_byte))
            nested_call_counter--;

    } while (nested_call_counter > 0);

    // We are in a return instruction, do the last step
    if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    // wait for the child
    waitpid(tid, &status, 0);

    // update the registers
    ptrace(PTRACE_GETREGS, tid, NULL, &stepping_thread->regs);

cleanup:
    // remove any installed breakpoint
    struct software_breakpoint *b = state->b_HEAD;
    while (b != NULL) {
        if (b->enabled) {
            ptrace(PTRACE_POKEDATA, tid, (void *)b->addr, b->instruction);
        }
        b = b->next;
    }

    Py_END_ALLOW_THREADS

    return Py_None;
}

static PyMethodDef Ptracer_methods[] = {
    {"attach", (PyCFunction)Ptracer_attach, METH_VARARGS, "Attach to a process"},
    {"setpid", (PyCFunction)Ptracer_setpid, METH_VARARGS, "Set the PID of the process to trace"},
    {"register_thread", (PyCFunction)Ptracer_register_thread, METH_VARARGS, "Register a thread"},
    {"unregister_thread", (PyCFunction)Ptracer_unregister_thread, METH_VARARGS, "Unregister a thread"},
    {"free_thread_list", (PyCFunction)Ptracer_free_thread_list, METH_NOARGS, "Free the thread list"},
    {"free_breakpoint_list", (PyCFunction)Ptracer_free_breakpoint_list, METH_NOARGS, "Free the breakpoint list"},
    {"detach_for_kill", (PyCFunction)Ptracer_detach_for_kill, METH_NOARGS, "Detach and kill the process"},
    {"set_options", (PyCFunction)Ptracer_set_options, METH_NOARGS, "Set the options for the tracer"},
    {"peek_data", (PyCFunction)Ptracer_peek_data, METH_VARARGS, "Peek data from the process"},
    {"poke_data", (PyCFunction)Ptracer_poke_data, METH_VARARGS, "Poke data into the process"},
    {"peek_user", (PyCFunction)Ptracer_peek_user, METH_VARARGS, "Peek user data from the process"},
    {"poke_user", (PyCFunction)Ptracer_poke_user, METH_VARARGS, "Poke user data into the process"},
    {"get_event_msg", (PyCFunction)Ptracer_get_event_msg, METH_VARARGS, "Get the event message"},
    {"singlestep", (PyCFunction)Ptracer_singlestep, METH_VARARGS, "Singlestep a thread"},
    {"cont_all_and_set_bps", (PyCFunction)Ptracer_cont_all_and_set_bps, METH_FASTCALL, "Continue all threads and set breakpoints"},
    {"wait_all_and_update_regs", (PyCFunction)Ptracer_wait_all_and_update_regs, METH_NOARGS, "Wait for all threads and update their registers"},
    {"deliver_signal_to_thread", (PyCFunction)Ptracer_deliver_signal_to_thread, METH_VARARGS, "Deliver a signal to a thread"},
    {"register_breakpoint", (PyCFunction)Ptracer_register_breakpoint, METH_VARARGS, "Register a breakpoint"},
    {"unregister_breakpoint", (PyCFunction)Ptracer_unregister_breakpoint, METH_VARARGS, "Unregister a breakpoint"},
    {"enable_breakpoint", (PyCFunction)enable_breakpoint, METH_VARARGS, "Enable a breakpoint"},
    {"disable_breakpoint", (PyCFunction)disable_breakpoint, METH_VARARGS, "Disable a breakpoint"},
    {"step_until", (PyCFunction)Ptracer_step_until, METH_VARARGS, "Step until a certain address"},
    {"detach_and_cont", (PyCFunction)ptrace_detach_and_cont, METH_NOARGS, "Detach and continue the process"},
    {"exact_finish", (PyCFunction)exact_finish, METH_VARARGS, "Finish the execution of a thread"},
    {NULL}
};

static PyTypeObject PtracerType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "libptrace.Ptracer",
    .tp_doc = "Ptracer objects",
    .tp_basicsize = sizeof(Ptracer),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Ptracer_new,
    .tp_dealloc = (destructor)Ptracer_dealloc,
    .tp_methods = Ptracer_methods,
};

static PyModuleDef libptrace_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = "libptrace",
    .m_doc = "libptrace Python module",
    .m_size = -1,
};

PyMODINIT_FUNC PyInit_libptrace(void) {
    PyObject* m;
    
    if (PyType_Ready(&PtracerType) < 0) {
        return NULL;
    }

    if (PyType_Ready(&ThreadRegsType) < 0) {
        return NULL;
    }

    m = PyModule_Create(&libptrace_module);
    if (m == NULL) {
        return NULL;
    }

    Py_INCREF(&PtracerType);
    Py_INCREF(&ThreadRegsType);

    PyModule_AddObject(m, "Ptracer", (PyObject*)&PtracerType);
    PyModule_AddObject(m, "ThreadRegs", (PyObject*)&ThreadRegsType);
    return m;    
}
