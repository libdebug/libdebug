#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.debugger.internal_debugger_instance_manager import (
    extend_internal_debugger,
    provide_internal_debugger,
)
from libdebug.liblog import liblog
from libdebug.snapshots.thread.thread_snapshot import ThreadSnapshot
from libdebug.utils.debugging_utils import resolve_address_in_maps
from libdebug.utils.pprint_primitives import pprint_backtrace_util, pprint_registers_all_util, pprint_registers_util
from libdebug.utils.signal_utils import resolve_signal_name, resolve_signal_number

if TYPE_CHECKING:
    from libdebug.data.register_holder import RegisterHolder
    from libdebug.data.registers import Registers
    from libdebug.debugger.debugger import Debugger
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.memory.abstract_memory_view import AbstractMemoryView


class ThreadContext(ABC):
    """This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack."""

    instruction_pointer: int
    """The thread's instruction pointer."""

    syscall_arg0: int
    """The thread's syscall argument 0."""

    syscall_arg1: int
    """The thread's syscall argument 1."""

    syscall_arg2: int
    """The thread's syscall argument 2."""

    syscall_arg3: int
    """The thread's syscall argument 3."""

    syscall_arg4: int
    """The thread's syscall argument 4."""

    syscall_arg5: int
    """The thread's syscall argument 5."""

    syscall_number: int
    """The thread's syscall number when the kernel has entered a syscall. Valid only when the thread is stopped inside a syscall."""

    syscall_return: int
    """The thread's syscall return value."""

    regs: Registers
    """The thread's registers."""

    _internal_debugger: InternalDebugger | None = None
    """The debugging context this thread belongs to."""

    _register_holder: RegisterHolder | None = None
    """The register holder object."""

    _dead: bool = False
    """Whether the thread is dead."""

    _exit_code: int | None = None
    """The thread's exit code."""

    _exit_signal: int | None = None
    """The thread's exit signal."""

    _signal_number: int = 0
    """The signal to forward to the thread."""

    _thread_id: int
    """The thread's ID."""

    _snapshot_count: int = 0
    """The number of snapshots taken."""

    _zombie: bool = False
    """Whether the thread is a zombie."""

    _invoked_syscall: int | None = None
    """The syscall number invoked on the thread, if currently so."""

    def __init__(self: ThreadContext, thread_id: int, registers: RegisterHolder) -> None:
        """Initializes the Thread Context."""
        self._internal_debugger = provide_internal_debugger(self)
        self._thread_id = thread_id
        self._register_holder = registers
        regs_class = self._register_holder.provide_regs_class()
        self.regs = regs_class(thread_id, self._register_holder.provide_regs())
        self._register_holder.apply_on_regs(self.regs, regs_class)

    def set_as_dead(self: ThreadContext) -> None:
        """Set the thread as dead."""
        self._dead = True

    @property
    def debugger(self: ThreadContext) -> Debugger:
        """The debugging context this thread belongs to."""
        return self._internal_debugger.debugger

    @property
    def dead(self: ThreadContext) -> bool:
        """Whether the thread is dead."""
        return self._dead

    @property
    def memory(self: ThreadContext) -> AbstractMemoryView:
        """The memory view of the debugged process."""
        return self._internal_debugger.memory

    @property
    def mem(self: ThreadContext) -> AbstractMemoryView:
        """Alias for the `memory` property.

        Get the memory view of the process.
        """
        return self._internal_debugger.memory

    @property
    def process_id(self: ThreadContext) -> int:
        """The process ID."""
        return self._internal_debugger.process_id

    @property
    def pid(self: ThreadContext) -> int:
        """Alias for `process_id` property.

        The process ID.
        """
        return self._internal_debugger.process_id

    @property
    def thread_id(self: ThreadContext) -> int:
        """The thread ID."""
        return self._thread_id

    @property
    def tid(self: ThreadContext) -> int:
        """The thread ID."""
        return self._thread_id

    @property
    def running(self: ThreadContext) -> bool:
        """Whether the process is running."""
        return self._internal_debugger.running

    @property
    def saved_ip(self: ThreadContext) -> int:
        """The return address of the current function."""
        self._internal_debugger._ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)

        try:
            return_address = stack_unwinder.get_return_address(self, self._internal_debugger.maps)
        except (OSError, ValueError) as e:
            raise ValueError(
                "Failed to get the return address. Check stack frame registers (e.g., base pointer).",
            ) from e

        return return_address

    @property
    def exit_code(self: ThreadContext) -> int | None:
        """The thread's exit code."""
        self._internal_debugger._ensure_process_stopped()
        if not self.dead:
            liblog.warning("Thread is not dead. No exit code available.")
        elif self._exit_code is None and self._exit_signal is not None:
            liblog.warning(
                "Thread exited with signal %s. No exit code available.",
                resolve_signal_name(self._exit_signal),
            )
        return self._exit_code

    @property
    def exit_signal(self: ThreadContext) -> str | None:
        """The thread's exit signal."""
        self._internal_debugger._ensure_process_stopped()
        if not self.dead:
            liblog.warning("Thread is not dead. No exit signal available.")
            return None
        elif self._exit_signal is None and self._exit_code is not None:
            liblog.warning("Thread exited with code %d. No exit signal available.", self._exit_code)
            return None
        return resolve_signal_name(self._exit_signal)

    @property
    def signal(self: ThreadContext) -> str | None:
        """The signal will be forwarded to the thread."""
        self._internal_debugger._ensure_process_stopped()
        return None if self._signal_number == 0 else resolve_signal_name(self._signal_number)

    @signal.setter
    def signal(self: ThreadContext, signal: str | int) -> None:
        """Set the signal to forward to the thread."""
        self._internal_debugger._ensure_process_stopped()
        if self._signal_number != 0:
            liblog.debugger(
                f"Overwriting signal {resolve_signal_name(self._signal_number)} with {resolve_signal_name(signal) if isinstance(signal, int) else signal}.",
            )
        if isinstance(signal, str):
            signal = resolve_signal_number(signal)
        self._signal_number = signal
        self._internal_debugger.resume_context.threads_with_signals_to_forward.append(self.thread_id)

    @property
    def signal_number(self: ThreadContext) -> int:
        """The signal number to forward to the thread."""
        return self._signal_number

    @property
    def zombie(self: ThreadContext) -> bool:
        """Whether the thread is a zombie."""
        return self._zombie

    def backtrace(self: ThreadContext, as_symbols: bool = False) -> list:
        """Returns the current backtrace of the thread.

        Args:
            as_symbols (bool, optional): Whether to return the backtrace as symbols
        """
        self._internal_debugger._ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)
        backtrace = stack_unwinder.unwind(self)
        if as_symbols:
            maps = self._internal_debugger.debugging_interface.get_maps()
            with extend_internal_debugger(self._internal_debugger):
                backtrace = [resolve_address_in_maps(x, maps) for x in backtrace]
        return backtrace

    def pprint_backtrace(self: ThreadContext) -> None:
        """Pretty prints the current backtrace of the thread."""
        self._internal_debugger._ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)
        backtrace = stack_unwinder.unwind(self)
        maps = self._internal_debugger.debugging_interface.get_maps()
        pprint_backtrace_util(backtrace, maps, self._internal_debugger.symbols)

    def pprint_registers(self: ThreadContext) -> None:
        """Pretty prints the thread's registers."""
        pprint_registers_util(
            self.regs,
            self._internal_debugger.maps,
            self._register_holder.provide_regs(),
        )

    def pprint_regs(self: ThreadContext) -> None:
        """Alias for the `pprint_registers` method.

        Pretty prints the thread's registers.
        """
        self.pprint_registers()

    def pprint_registers_all(self: ThreadContext) -> None:
        """Pretty prints all the thread's registers."""
        pprint_registers_all_util(
            self.regs,
            self._internal_debugger.maps,
            self._register_holder.provide_regs(),
            self._register_holder.provide_special_regs(),
            self._register_holder.provide_vector_fp_regs(),
        )

    def pprint_regs_all(self: ThreadContext) -> None:
        """Alias for the `pprint_registers_all` method.

        Pretty prints all the thread's registers.
        """
        self.pprint_registers_all()

    def step(self: ThreadContext) -> None:
        """Executes a single instruction of the process."""
        self._internal_debugger.step(self)

    def step_until(
        self: ThreadContext,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        self._internal_debugger.step_until(self, position, max_steps, file)

    def finish(self: ThreadContext, heuristic: str = "backtrace") -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(self, heuristic=heuristic)

    def next(self: ThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_debugger.next(self)

    def si(self: ThreadContext) -> None:
        """Alias for the `step` method.

        Executes a single instruction of the process.
        """
        self._internal_debugger.step(self)

    def su(
        self: ThreadContext,
        position: int | str,
        max_steps: int = -1,
    ) -> None:
        """Alias for the `step_until` method.

        Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        self._internal_debugger.step_until(self, position, max_steps)

    def fin(self: ThreadContext, heuristic: str = "backtrace") -> None:
        """Alias for the `finish` method. Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(self, heuristic)

    def ni(self: ThreadContext) -> None:
        """Alias for the `next` method. Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_debugger.next(self)

    def invoke_syscall(self: ThreadContext, syscall_identifier: str | int, *args: int) -> int:
        """Invokes a syscall with the specified arguments on this thread.

        Args:
            syscall_identifier (str | int): The syscall identifier.
            *args (int): The syscall arguments.
        """
        liblog.debugger(f"Invoking syscall {syscall_identifier} on thread {self.tid} with args {args}")
        return self._internal_debugger.invoke_syscall(self, syscall_identifier, *args)

    def __repr__(self: ThreadContext) -> str:
        """Returns a string representation of the object."""
        repr_str = "ThreadContext()\n"
        repr_str += f"  Thread ID: {self.thread_id}\n"
        repr_str += f"  Process ID: {self.process_id}\n"
        repr_str += f"  Instruction Pointer: {self.instruction_pointer:#x}\n"
        repr_str += f"  Dead: {self.dead}"
        return repr_str

    def create_snapshot(self: ThreadContext, level: str = "base", name: str | None = None) -> ThreadSnapshot:
        """Create a snapshot of the current thread state.

        Snapshot levels:
        - base: Registers
        - writable: Registers, writable memory contents
        - full: Registers, all readable memory contents

        Args:
            level (str): The level of the snapshot.
            name (str, optional): The name of the snapshot. Defaults to None.

        Returns:
            ThreadSnapshot: The created snapshot.
        """
        self._internal_debugger._ensure_process_stopped()
        return ThreadSnapshot(self, level, name)

    def notify_snapshot_taken(self: ThreadContext) -> None:
        """Notify the thread that a snapshot has been taken."""
        self._snapshot_count += 1

    @property
    def num_syscall_args(self: ThreadContext) -> int:
        """The number of syscall arguments."""
        return 6
