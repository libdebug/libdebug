#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.signal_hook import SignalHook
    from libdebug.data.syscall_hook import SyscallHook
    from libdebug.state.thread_context import ThreadContext


class DebuggingInterface(ABC):
    """The interface used by `_InternalDebugger` to communicate with the available debugging backends, such as `ptrace` or `gdb`."""

    def __init__(self: DebuggingInterface) -> None:
        """Initializes the DebuggingInterface classs."""

    @abstractmethod
    def reset(self: DebuggingInterface) -> None:
        """Resets the state of the interface."""

    @abstractmethod
    def run(self: DebuggingInterface) -> None:
        """Runs the specified process."""

    @abstractmethod
    def attach(self: DebuggingInterface, pid: int) -> None:
        """Attaches to the specified process.

        Args:
            pid (int): the pid of the process to attach to.
        """

    @abstractmethod
    def detach(self: DebuggingInterface) -> None:
        """Detaches from the process."""

    @abstractmethod
    def kill(self: DebuggingInterface) -> None:
        """Instantly terminates the process."""

    @abstractmethod
    def cont(self: DebuggingInterface) -> None:
        """Continues the execution of the process."""

    @abstractmethod
    def wait(self: DebuggingInterface) -> None:
        """Waits for the process to stop."""

    @abstractmethod
    def migrate_to_gdb(self: DebuggingInterface) -> None:
        """Migrates the current process to GDB."""

    @abstractmethod
    def migrate_from_gdb(self: DebuggingInterface) -> None:
        """Migrates the current process from GDB."""

    @abstractmethod
    def step(self: DebuggingInterface, thread: ThreadContext) -> None:
        """Executes a single instruction of the specified thread.

        Args:
            thread (ThreadContext): The thread to step.
        """

    @abstractmethod
    def step_until(self: DebuggingInterface, thread: ThreadContext, address: int, max_steps: int) -> None:
        """Executes instructions of the specified thread until the specified address is reached.

        Args:
            thread (ThreadContext): The thread to step.
            address (int): The address to reach.
            max_steps (int): The maximum number of steps to execute.
        """

    @abstractmethod
    def finish(self: DebuggingInterface, thread: ThreadContext, exact: bool) -> None:
        """Executes instructions of the specified thread until the current function returns.

        Args:
            thread (ThreadContext): The thread to step.
            exact (bool): If True, the command is implemented as a series of `step` commands.
        """

    @abstractmethod
    def maps(self: DebuggingInterface) -> list[MemoryMap]:
        """Returns the memory maps of the process."""

    @abstractmethod
    def set_breakpoint(self: DebuggingInterface, bp: Breakpoint) -> None:
        """Sets a breakpoint at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to set.
        """

    @abstractmethod
    def unset_breakpoint(self: DebuggingInterface, bp: Breakpoint) -> None:
        """Restores the original instruction flow at the specified address.

        Args:
            bp (Breakpoint): The breakpoint to restore.
        """

    @abstractmethod
    def set_syscall_hook(self: DebuggingInterface, hook: SyscallHook) -> None:
        """Sets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to set.
        """

    @abstractmethod
    def unset_syscall_hook(self: DebuggingInterface, hook: SyscallHook) -> None:
        """Unsets a syscall hook.

        Args:
            hook (SyscallHook): The syscall hook to unset.
        """

    @abstractmethod
    def set_signal_hook(self: DebuggingInterface, hook: SignalHook) -> None:
        """Sets a signal hook.

        Args:
            hook (SignalHook): The signal hook to set.
        """

    @abstractmethod
    def unset_signal_hook(self: DebuggingInterface, hook: SignalHook) -> None:
        """Unsets a signal hook.

        Args:
            hook (SignalHook): The signal hook to unset.
        """

    @abstractmethod
    def peek_memory(self: DebuggingInterface, address: int) -> int:
        """Reads the memory at the specified address.

        Args:
            address (int): The address to read.

        Returns:
            int: The read memory value.
        """

    @abstractmethod
    def poke_memory(self: DebuggingInterface, address: int, data: int) -> None:
        """Writes the memory at the specified address.

        Args:
            address (int): The address to write.
            data (int): The value to write.
        """
