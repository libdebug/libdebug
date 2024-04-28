#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from abc import ABC, abstractmethod

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_map import MemoryMap
from libdebug.data.register_holder import RegisterHolder
from libdebug.data.syscall_hook import SyscallHook
from libdebug.data.signal_hook import SignalHook
from libdebug.state.debugging_context import provide_context
from libdebug.state.thread_context import ThreadContext


class DebuggingInterface(ABC):
    """The interface used by `_InternalDebugger` to communicate with the available debugging backends, such as `ptrace` or `gdb`."""

    breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process.
    Key: the address of the breakpoint."""

    threads: dict[int, ThreadContext]
    """A dictionary of all the threads of the process.
    Key: the thread ID."""

    def __init__(self):
        self.breakpoints = provide_context(self)._breakpoints
        self.threads = provide_context(self)._threads

    @abstractmethod
    def reset(self):
        """Resets the state of the interface."""
        pass

    @abstractmethod
    def run(self):
        """Runs the specified process."""
        pass

    @abstractmethod
    def attach(self, pid: int):
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """
        pass

    @abstractmethod
    def kill(self):
        """Instantly terminates the process."""
        pass

    @abstractmethod
    def cont(self):
        """Continues the execution of the process."""
        pass

    @abstractmethod
    def wait(self):
        """Waits for the process to stop."""
        pass

    @abstractmethod
    def migrate_to_gdb(self):
        """Migrates the current process to GDB."""
        pass

    @abstractmethod
    def migrate_from_gdb(self):
        """Migrates the current process from GDB."""
        pass

    @abstractmethod
    def step(self, thread: ThreadContext):
        """Executes a single instruction of the specified thread.

        Args:
            thread (ThreadContext): The thread to step.
        """
        pass

    @abstractmethod
    def step_until(self, thread: ThreadContext, address: int, max_steps: int):
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """
        pass

    @abstractmethod
    def maps(self) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        pass

    @abstractmethod
    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers for the specified thread.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    @abstractmethod
    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        pass

    @abstractmethod
    def unset_breakpoint(self, breakpoint: Breakpoint):
        """Restores the original instruction flow at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to restore.
        """
        pass

    @abstractmethod
    def set_syscall_hook(self, hook: SyscallHook):
        """Sets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to set.
        """
        pass

    @abstractmethod
    def unset_syscall_hook(self, hook: SyscallHook):
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """
        pass
    
    @abstractmethod
    def set_signal_hook(self, hook: SignalHook):
        """Sets a signal hook.

        Args:
            hook (SignalHook): The signal hook to set.
        """
        pass

    @abstractmethod
    def unset_signal_hook(self, hook: SignalHook):
        """Unsets a signal hook.

        Args:
            hook (SignalHook): The signal hook to unset.
        """
        pass

    @abstractmethod
    def peek_memory(self, address: int) -> int:
        """Reads the memory at the specified address.

        Args:
            address (int): The address to read.

        Returns:
            int: The read memory value.
        """
        pass

    @abstractmethod
    def poke_memory(self, address: int, data: int):
        """Writes the memory at the specified address.

        Args:
            address (int): The address to write.
            data (int): The value to write.
        """
        pass
