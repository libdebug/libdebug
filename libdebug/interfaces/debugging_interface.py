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

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.state.debugging_context import debugging_context
from libdebug.state.thread_context import ThreadContext


class DebuggingInterface:
    """The interface used by `Debugger` to communicate with the available debugging backends, such as `ptrace` or `gdb`."""

    breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process.
    Key: the address of the breakpoint."""

    threads: dict[int, ThreadContext]
    """A dictionary of all the threads of the process.
    Key: the thread ID."""

    def __init__(self):
        self.breakpoints = debugging_context._breakpoints
        self.threads = debugging_context._threads

    def reset(self):
        """Resets the state of the interface."""
        pass

    def run(self):
        """Runs the specified process."""
        pass

    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        pass

    def kill(self):
        """Instantly terminates the process."""
        pass

    def cont(self):
        """Continues the execution of the process."""
        pass

    def wait(self):
        """Waits for the process to stop."""
        pass

    def step(self, thread: ThreadContext):
        """Executes a single instruction of the specified thread.

        Args:
            thread (ThreadContext): The thread to step.
        """
        pass

    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        pass

    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        pass

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers for the specified thread.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        pass

    def unset_breakpoint(self, breakpoint: Breakpoint):
        """Restores the original instruction flow at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to restore.
        """
        pass

    def disable_aslr(self):
        """Disables ASLR for the current process."""
        pass

    def peek_memory(self, address: int) -> int:
        """Reads the memory at the specified address.

        Args:
            address (int): The address to read.

        Returns:
            int: The read memory value.
        """
        pass

    def poke_memory(self, address: int, data: int):
        """Writes the memory at the specified address.

        Args:
            address (int): The address to write.
            data (int): The value to write.
        """
        pass
