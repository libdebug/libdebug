#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog
from libdebug.utils.debugging_utils import resolve_address_in_maps
from libdebug.utils.signal_utils import resolve_signal_name, resolve_signal_number

if TYPE_CHECKING:
    from libdebug.data.memory_view import MemoryView
    from libdebug.data.register_holder import RegisterHolder
    from libdebug.debugger.internal_debugger import InternalDebugger


class ThreadContext:
    """This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack."""

    instruction_pointer: int
    """The thread's instruction pointer."""
    
    _internal_debugger: InternalDebugger | None = None
    """The debugging context this thread belongs to."""

    _thread_dead: bool = False
    """Whether the thread is dead."""

    _exit_code: int | None = None
    """The thread's exit code."""

    _exit_signal: int | None = None
    """The thread's exit signal."""

    _signal_number: int = 0
    """The signal to forward to the thread."""

    _thread_id: int
    """The thread's ID."""

    def __init__(self: ThreadContext, thread_id: int, registers: RegisterHolder) -> None:
        """Initializes the Thread Context."""
        self._internal_debugger = provide_internal_debugger(self)
        self._thread_id = thread_id
        regs_class = registers.provide_regs_class()
        self.regs = regs_class()
        registers.apply_on_regs(self.regs, regs_class)
        registers.apply_on_thread(self, ThreadContext)


    def set_as_dead(self: ThreadContext) -> None:
        """Set the thread as dead."""
        self._thread_dead = True
        
    @property
    def thread_dead(self: ThreadContext) -> bool:
        """Whether the thread is dead."""
        return self._thread_dead

    @property
    def tdead(self: ThreadContext) -> bool:
        """Whether the thread is dead."""
        return self._thread_dead

    @property
    def process_dead(self: ThreadContext) -> bool:
        """Check if the process is dead."""
        return self._internal_debugger.dead

    @property
    def pdead(self: ThreadContext) -> bool:
        """Check if the process is dead."""
        return self._internal_debugger.dead

    @property
    def memory(self: ThreadContext) -> MemoryView:
        """The memory view of the debugged process."""
        return self._internal_debugger.memory

    @property
    def process_id(self: ThreadContext) -> int:
        """The process ID of the thread."""
        return self._internal_debugger.process_id

    @property
    def pid(self: ThreadContext) -> int:
        """The process ID of the thread."""
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
    def signal(self: ThreadContext) -> str | None:
        """The signal will be forwarded to the thread."""
        self._internal_debugger._ensure_process_stopped()
        return (
            None
            if self._signal_number == 0
            else resolve_signal_name(self._signal_number)
        )

    @property
    def exit_code(self: ThreadContext) -> int | None:
        """The thread's exit code."""
        self._internal_debugger._ensure_process_stopped()
        if not self.thread_dead:
            liblog.warning("Thread is not dead. No exit code available.")
        elif self._exit_code is None and self._exit_signal is not None:
            liblog.warning(
                "Thread exited with signal %s. No exit code available.",
                resolve_signal_name(self._exit_signal),
            )
        return self._exit_code

    @property
    def exit_signal(self: ThreadContext) -> int | None:
        """The thread's exit signal."""
        self._internal_debugger._ensure_process_stopped()
        if not self.thread_dead:
            liblog.warning("Thread is not dead. No exit signal available.")
            return None
        elif self._exit_signal is None and self._exit_code is not None:
            liblog.warning(
                "Thread exited with code %d. No exit signal available.", self._exit_code
            )
            return None
        return resolve_signal_name(self._exit_signal)

    @signal.setter
    def signal(self: ThreadContext, signal: str | int) -> None:
        """Set the signal to forward to the thread."""
        self._internal_debugger._ensure_process_stopped()
        if self._signal_number != 0:
            liblog.debugger(
                f"Overwriting signal {resolve_signal_name(self._signal_number)} with {resolve_signal_name(signal) if isinstance(signal, int) else signal}."
            )
        if isinstance(signal, str):
            signal = resolve_signal_number(signal)
        self._signal_number = signal
        self._internal_debugger.resume_context.threads_with_signals_to_forward.append(
            self.process_id
        )

    def backtrace(self: ThreadContext) -> list:
        """Returns the current backtrace of the thread."""
        internal_debugger = self._internal_debugger
        internal_debugger._ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider()
        backtrace = stack_unwinder.unwind(self)
        maps = internal_debugger.debugging_interface.maps()
        return [resolve_address_in_maps(x, maps) for x in backtrace]

    def current_return_address(self: ThreadContext) -> int:
        """Returns the return address of the current function."""
        self._internal_debugger._ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider()
        return stack_unwinder.get_return_address(self)

    def step(self: ThreadContext) -> None:
        """Executes a single instruction of the process."""
        self._internal_debugger.step(self)

    def step_until(
        self: ThreadContext,
        position: int | str,
        max_steps: int = -1,
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        self._internal_debugger.step_until(self, position, max_steps)

    def finish(self: ThreadContext, exact: bool = True) -> None:
        """Continues the process until the current function returns or the process stops.

        When used in step mode, it will step until a return instruction is executed. Otherwise, it uses a heuristic
        based on the call stack to breakpoint (exact is slower).

        Args:
            exact (bool, optional): Whether or not to execute in step mode. Defaults to True.
        """
        self._internal_debugger.finish(self, exact)
