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

from enum import IntEnum

PTRACE_EVENT_FORK       = 1
PTRACE_EVENT_VFORK      = 2
PTRACE_EVENT_CLONE      = 3
PTRACE_EVENT_EXEC       = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT       = 6
PTRACE_EVENT_SECCOMP    = 7

SIGTRAP                 = 5
SYSCALL_SIGTRAP         = 0x80 | SIGTRAP


class StopEvents(IntEnum):
    CLONE_EVENT = (SIGTRAP | (PTRACE_EVENT_CLONE << 8))
    EXEC_EVENT = (SIGTRAP | (PTRACE_EVENT_EXEC << 8))
    EXIT_EVENT = (SIGTRAP | (PTRACE_EVENT_EXIT << 8))
    FORK_EVENT = (SIGTRAP | (PTRACE_EVENT_FORK << 8))
    VFORK_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK << 8))
    VFORK_DONE_EVENT = (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8))
    SECCOMP_EVENT = (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))
