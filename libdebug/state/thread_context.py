#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.liblog import liblog
from libdebug.state.debugging_context import debugging_context
from libdebug.utils.debugging_utils import resolve_address_in_maps
from libdebug.utils.signal_utils import resolve_signal_name, resolve_signal_number

if TYPE_CHECKING:
    from libdebug.data.memory_view import MemoryView
    from libdebug.data.register_holder import RegisterHolder
    from libdebug.state.debugging_context import DebuggingContext


class ThreadContext:
    """This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack."""

    context: DebuggingContext | None = None
    """The debugging context this thread belongs to."""

    dead: bool = False
    """Whether the thread is dead."""

    instruction_pointer: int
    """The thread's instruction pointer."""

    registers: RegisterHolder | None = None
    """The register holder object. It provides access to the thread's registers."""

    _signal_number: int = 0
    """The signal to forward to the thread."""

    _thread_id: int
    """The thread's ID."""

    _dirty: bool = False
    """Whether the registers have been modified."""

    _needs_register_poll: bool = True
    """Whether the registers need to be polled."""

    _needs_sigcont: bool = False
    """Whether the thread needs to be continued after a signal stop."""

    def __init__(self: ThreadContext, thread_id: int) -> None:
        """Initializes the Thread Context."""
        self._thread_id = thread_id

    @staticmethod
    def new(thread_id: int | None = None, registers: RegisterHolder | None = None) -> ThreadContext:
        """Creates a new thread context object.

        Args:
            thread_id (int, optional): The thread's ID. Defaults to None.
            registers (RegisterHolder): The register view associated with the thread.

        Returns:
            ThreadContext: The thread context object.
        """
        if thread_id is None:
            # If no thread ID is specified, we assume the main thread which has tid = pid
            thread_id = debugging_context().process_id

        if registers is None:
            raise RuntimeError("A register view must be provided during ThreadContext initialization.")

        thread = ThreadContext(thread_id)
        thread.registers = registers
        thread.registers.apply_on(thread, ThreadContext)

        thread.context = debugging_context()

        return thread

    @property
    def memory(self: ThreadContext) -> MemoryView:
        """The memory view of the debugged process."""
        return self.context.memory

    @property
    def process_id(self: ThreadContext) -> int:
        """The process ID of the thread."""
        return self.context.process_id

    @property
    def pid(self: ThreadContext) -> int:
        """The process ID of the thread."""
        return self.context.process_id

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
        return None if self._signal_number == 0 else resolve_signal_name(self._signal_number)

    @signal.setter
    def signal(self: ThreadContext, signal: str | int) -> None:
        """Set the signal to forward to the thread."""
        if self._signal_number != 0:
            liblog.debugger(
                f"Overwriting signal {resolve_signal_name(self._signal_number)} with {resolve_signal_name(signal) if isinstance(signal, int) else signal}."
            )
        if isinstance(signal, str):
            signal = resolve_signal_number(signal)
        self._signal_number = signal
        self.context._resume_context.threads_with_signals_to_forward.append(self.process_id)

    def _poll_registers(self: ThreadContext) -> None:
        """Updates the register values."""
        if not self._needs_register_poll:
            self._needs_register_poll = True
            return

        liblog.debugger("Polling registers for thread %d", self.thread_id)

        self.registers.poll(self)
        self._dirty = False

    def _flush_registers(self: ThreadContext) -> None:
        """Flushes the register values."""
        liblog.debugger("Flushing registers for thread %d", self.thread_id)

        if self._dirty:
            self.registers.flush(self)

    def backtrace(self: ThreadContext) -> list:
        """Returns the current backtrace of the thread."""
        stack_unwinder = stack_unwinding_provider()
        backtrace = stack_unwinder.unwind(self)
        maps = self.context.debugging_interface.maps()
        return [resolve_address_in_maps(x, maps) for x in backtrace]

    def current_return_address(self: ThreadContext) -> int:
        """Returns the return address of the current function."""
        stack_unwinder = stack_unwinding_provider()
        return stack_unwinder.get_return_address(self)
