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
    typedef struct {
        int pid;
        uint64_t addr;
        uint64_t bp_instruction;
        uint64_t prev_instruction;
    } ptrace_hit_bp;

    int ptrace_trace_me(void);
    int ptrace_attach(int pid);
    int ptrace_detach(int pid);
    void ptrace_set_options(int pid);

    int ptrace_getregs(int pid, void *regs);
    int ptrace_setregs(int pid, void *regs);

    int ptrace_singlestep(int pid);

    uint64_t ptrace_peekdata(int pid, uint64_t addr);
    uint64_t ptrace_pokedata(int pid, uint64_t addr, uint64_t data);
    uint64_t ptrace_peekuser(int pid, uint64_t addr);
    uint64_t ptrace_pokeuser(int pid, uint64_t addr, uint64_t data);

    uint64_t ptrace_geteventmsg(int pid);

    int cont_all_and_set_bps(
        size_t n_pids,
        int *pids,
        size_t n_addrs,
        ptrace_hit_bp *bps
    );

    int interrupt_other_threads(
        int pid,
        size_t n_tids,
        int *tids
    );
"""
)

ffibuilder.set_source(
    "libdebug.cffi._ptrace_cffi",
    """
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>


typedef struct {
    int pid;
    uint64_t addr;
    uint64_t bp_instruction;
    uint64_t prev_instruction;
} ptrace_hit_bp;


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


int ptrace_getregs(int pid, void *regs)
{
    return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

int ptrace_setregs(int pid, void *regs)
{
    return ptrace(PTRACE_SETREGS, pid, NULL, regs);
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

uint64_t ptrace_geteventmsg(int pid)
{
    uint64_t data;

    ptrace(PTRACE_GETEVENTMSG, pid, NULL, &data);

    return data;
}


int cont_all_and_set_bps(
    size_t n_pids,
    int *pids,
    size_t n_addrs,
    ptrace_hit_bp *bps
) {
    int status = 0;

    // restore the previous instruction for any thread that hit a software breakpoint
    for (size_t i = 0; i < n_addrs; i++) {
        // restore the previous instruction
        if (ptrace(PTRACE_POKEDATA, bps[i].pid, (void*) bps[i].addr, bps[i].prev_instruction))
            return -1;

        // step over the breakpoint
        if (ptrace(PTRACE_SINGLESTEP, bps[i].pid, NULL, NULL))
            return -1;

        // wait for the child
        waitpid(bps[i].pid, &status, 0);

        // restore the breakpoint
        if (ptrace(PTRACE_POKEDATA, bps[i].pid, (void*) bps[i].addr, bps[i].bp_instruction))
            return -1;
    }

    // continue the execution
    for (size_t i = 0; i < n_pids; i++) {
        status += ptrace(PTRACE_CONT, pids[i], NULL, NULL);
    }

    return status;
}

int interrupt_other_threads(
    int pid,
    size_t n_tids,
    int *tids
) {
    for (int i = 0; i < n_tids; i++)
        tgkill(pid, tids[i], SIGSTOP);

    return 0;
}
""",
    libraries=[],
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
