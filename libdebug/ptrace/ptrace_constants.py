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

from enum import IntEnum

NULL                    = 0
PTRACE_TRACEME          = 0
PTRACE_PEEKTEXT         = 1
PTRACE_PEEKDATA         = 2
PTRACE_PEEKUSER         = 3
PTRACE_POKETEXT         = 4
PTRACE_POKEDATA         = 5
PTRACE_POKEUSER         = 6
PTRACE_CONT             = 7
PTRACE_KILL             = 8
PTRACE_SINGLESTEP       = 9
PTRACE_GETREGS          = 12
PTRACE_SETREGS          = 13
PTRACE_GETFPREGS        = 14
PTRACE_SETFPREGS        = 15
PTRACE_ATTACH           = 16
PTRACE_DETACH           = 17
PTRACE_GETFPXREGS       = 18
PTRACE_SETFPXREGS       = 19
PTRACE_SYSCALL          = 24
PTRACE_GET_THREAD_AREA  = 25
PTRACE_SET_THREAD_AREA  = 26
PTRACE_SETOPTIONS       = 0x4200
PTRACE_GETEVENTMSG      = 0x4201
PTRACE_GETSIGINFO       = 0x4202
PTRACE_SETSIGINFO       = 0x4203
PTRACE_INTERRUPT        = 0x4207
PTRACE_O_TRACESYSGOOD   = 1 << 0
PTRACE_O_TRACEFORK      = 1 << 1
PTRACE_O_TRACEVFORK     = 1 << 2
PTRACE_O_TRACECLONE     = 1 << 3
PTRACE_O_TRACEEXEC      = 1 << 4
PTRACE_O_TRACEVFORKDONE = 1 << 5
PTRACE_O_TRACEEXIT      = 1 << 6
PTRACE_O_MASK           = 1 << 7 - 1
PTRACE_EVENT_FORK       = 1
PTRACE_EVENT_VFORK      = 2
PTRACE_EVENT_CLONE      = 3
PTRACE_EVENT_EXEC       = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT       = 6
PTRACE_EVENT_SECCOMP    = 7

WNOHANG                 = 1
SIGTRAP                 = 5


class StopEvents(IntEnum):
    CLONE_EVENT = (SIGTRAP | (PTRACE_EVENT_CLONE << 8))
    EXEC_EVENT = (SIGTRAP | (PTRACE_EVENT_EXEC << 8))
    EXIT_EVENT = (SIGTRAP | (PTRACE_EVENT_EXIT << 8))
    FORK_EVENT = (SIGTRAP | (PTRACE_EVENT_FORK << 8))
    VFORK_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK << 8))
    VFORK_DONE_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8))
    SECCOMP_EVENT = (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))
