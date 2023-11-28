#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

from cffi import FFI

ffibuilder = FFI()
ffibuilder.cdef(
    """
    int ptrace_trace_me(void);
    int ptrace_attach(int pid);
    int ptrace_detach(int pid);
    void ptrace_set_options(int pid);

    int ptrace_getregs(int pid, void *regs);
    int ptrace_setregs(int pid, void *regs);

    int ptrace_cont(int pid);
    int ptrace_singlestep(int pid);

    uint64_t ptrace_peekdata(int pid, uint64_t addr);
    uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data);
    uint64_t ptrace_peekuser(int pid, uint64_t addr);
    uint64_t ptrace_pokeuser(int pid, uint64_t addr, uint64_t data);


    int cont_after_bp(int pid, uint64_t addr, uint64_t prev_data, uint64_t data);
"""
)

ffibuilder.set_source(
    "libdebug.cffi._ptrace_cffi",
    """
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>


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
    int options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
}


int ptrace_getregs(int pid, void *regs)
{
    return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

int ptrace_setregs(int pid, void *regs)
{
    return ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

int ptrace_cont(int pid)
{
    return ptrace(PTRACE_CONT, pid, NULL, NULL);
}

int ptrace_singlestep(int pid)
{
    return ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
}

uint64_t ptrace_peekdata(int pid, uint64_t addr)
{
    return ptrace(PTRACE_PEEKDATA, pid, (void*) addr, NULL);
}

uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data)
{
    return ptrace(PTRACE_POKEDATA, pid, (void*) addr, data);
}

uint64_t ptrace_peekuser(int pid, uint64_t addr)
{
    return ptrace(PTRACE_PEEKUSER, pid, addr, NULL);
}

uint64_t ptrace_pokeuser(int pid, uint64_t addr, uint64_t data)
{
    return ptrace(PTRACE_POKEUSER, pid, addr, data);
}


int cont_after_bp(int pid, uint64_t addr, uint64_t prev_data, uint64_t data)
{
    int status;

    // restore the previous instruction
    status = ptrace(PTRACE_POKEDATA, pid, (void*) addr, prev_data);

    if (status == -1) {
        return status;
    }

    // step over the breakpoint
    status = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

    if (status == -1) {
        return status;
    }

    // wait for the child
    waitpid(pid, &status, 1 << 30);

    // restore the breakpoint
    status = ptrace(PTRACE_POKEDATA, pid, (void*) addr, data);

    if (status == -1) {
        return status;
    }

    // continue the execution
    status = ptrace(PTRACE_CONT, pid, NULL, NULL);

    return status;
}
""",
    libraries=[],
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
