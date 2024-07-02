//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define PY_SSIZE_T_CLEAN
#include <Python.h>

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
    int signal_to_deliver;
    struct thread *next;
};

struct tracer_state {
    pid_t process_id;
    struct thread *t_HEAD;
    struct software_breakpoint *b_HEAD;
    _Bool syscall_hooks_enabled;
};

typedef struct {
    PyObject_HEAD
    struct tracer_state state;
} Ptracer;

static void Ptracer_dealloc(Ptracer *self)
{
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject* Ptracer_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Ptracer *self;

    self = (Ptracer *) type->tp_alloc(type, 0);

    self->state.t_HEAD = NULL;
    self->state.b_HEAD = NULL;
    self->state.syscall_hooks_enabled = 0;

    return (PyObject *) self;
}

static PyObject* Ptracer_setpid(Ptracer *self, PyObject *arg)
{
    if (!PyLong_Check(arg)) {
        PyErr_SetString(PyExc_TypeError, "Bad type");
        return (PyObject *) NULL;
    }

    self->state.process_id = (pid_t) PyLong_AsUnsignedLong(arg);

    Py_RETURN_NONE;
}

static int Ptracer_init(Ptracer *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyMemberDef Ptracer_members[] = {
    { NULL }
};

static PyMethodDef Ptracer_methods[] = {
    { "setPid", (PyCFunction) Ptracer_setpid, METH_O | METH_FASTCALL | METH_CLASS, "Sets the process id" },
    { NULL }
};

static PyTypeObject Ptracer_t = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "libptrace.Ptracer",
    .tp_doc = PyDoc_STR("Ptracer Class"),
    .tp_basicsize = sizeof(Ptracer),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = Ptracer_new,
    .tp_init = (initproc) Ptracer_init,
    .tp_dealloc = (destructor) Ptracer_dealloc,
    .tp_members = Ptracer_members,
    .tp_methods = Ptracer_methods,
};

static PyModuleDef libptrace = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "libptrace",
    .m_doc = "Native extension for cross-platform ptrace integration.",
    .m_size = -1,
};

PyMODINIT_FUNC
PyInit_libptrace()
{
    PyObject *ptracer;
    if (PyType_Ready(&Ptracer_t) < 0)
        return NULL;

    PyObject *m = PyModule_Create(&libptrace);
    if (m == NULL)
        return NULL;

    Py_INCREF(&Ptracer_t);
    if (PyModule_AddObject(m, "Ptracer", (PyObject *) &Ptracer_t) < 0) {
        Py_DECREF(&Ptracer_t);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
