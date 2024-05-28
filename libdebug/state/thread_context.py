#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations
from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.data.register_holder import RegisterHolder
from libdebug.liblog import liblog
from libdebug.state.debugging_context import debugging_context
from libdebug.utils.debugging_utils import resolve_address_in_maps

if TYPE_CHECKING:
    from libdebug.state.debugging_context import DebuggingContext


class ThreadContext:
    """
    This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack.
    """

    context: "DebuggingContext" | None = None
    """The debugging context this thread belongs to."""

    dead: bool = False
    """Whether the thread is dead."""

    instruction_pointer: int
    """The thread's instruction pointer."""

    process_id: int
    """The process ID of the thread."""

    registers: RegisterHolder | None = None
    """The register holder object. It provides access to the thread's registers."""

    signal_number: int = 0
    """The signal to deliver to the thread."""

    thread_id: int
    """The thread's ID."""

    _dirty: bool = False
    """Whether the registers have been modified."""

    _needs_register_poll: bool = True
    """Whether the registers need to be polled."""

    _needs_sigcont: bool = False
    """Whether the thread needs to be continued after a signal stop."""

    def __init__(self, thread_id: int):
        self.thread_id = thread_id

    @staticmethod
    def new(thread_id: int | None = None, registers: RegisterHolder | None = None):
        """Creates a new thread context object.

        Args:
            thread_id (int, optional): The thread's ID. Defaults to None.

        Returns:
            ThreadContext: The thread context object.
        """
        if thread_id is None:
            # If no thread ID is specified, we assume the main thread which has tid = pid
            thread_id = debugging_context().process_id

        thread = ThreadContext(thread_id)
        thread.registers = registers
        thread.registers.apply_on(thread, ThreadContext)

        thread.context = debugging_context()

        return thread

    @property
    def memory(self):
        """The memory view of the debugged process."""
        return self.context.memory

    @property
    def process_id(self):
        """The process ID of the thread."""
        return self.context.process_id

    def _poll_registers(self):
        """Updates the register values."""
        if not self._needs_register_poll:
            self._needs_register_poll = True
            return

        liblog.debugger("Polling registers for thread %d", self.thread_id)

        self.registers.poll(self)
        self._dirty = False

    def _flush_registers(self):
        """Flushes the register values."""
        liblog.debugger("Flushing registers for thread %d", self.thread_id)

        if self._dirty:
            self.registers.flush(self)

    def backtrace(self):
        """Returns the current backtrace of the thread."""
        stack_unwinder = stack_unwinding_provider()
        backtrace = stack_unwinder.unwind(self)
        return list(
            map(
                lambda x: resolve_address_in_maps(
                    x, self.context.debugging_interface.maps()
                ),
                backtrace,
            )
        )

    def current_return_address(self):
        """Returns the return address of the current function."""
        stack_unwinder = stack_unwinding_provider()
        return stack_unwinder.get_return_address(self)
