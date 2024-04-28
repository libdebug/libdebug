#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.data.register_holder import RegisterHolder
from libdebug.liblog import liblog
from libdebug.state.debugging_context import debugging_context, provide_context
from libdebug.utils.debugging_utils import resolve_address_in_maps


class ThreadContext:
    """
    This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack.
    """

    dead: bool = False
    """Whether the thread is dead."""

    registers: RegisterHolder | None = None
    """The register holder object. It provides access to the thread's registers."""

    thread_id: int
    """The thread's ID."""

    instruction_pointer: int
    """The thread's instruction pointer."""
    
    signal_to_deliver: int = 0
    """The signal to deliver to the thread."""

    _needs_register_poll: bool = True
    """Whether the registers need to be polled."""

    _needs_sigcont: bool = False
    """Whether the thread needs to be continued after a signal stop."""

    _dirty: bool = False
    """Whether the registers have been modified."""

    _in_background_op: bool = False
    """Whether the thread is being interacted with from the background thread."""

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

        return thread

    @property
    def memory(self):
        """The memory view of the debugged process."""
        # This is not the best way to do it, but it should not cause issues
        # Even if the library is multi-threaded, we don't expect the memory view
        # to be used while a background operation is in progress
        if not self._in_background_op:
            return provide_context(self).memory
        else:
            return provide_context(self)._threaded_memory

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
                    x, provide_context(self).debugging_interface.maps()
                ),
                backtrace,
            )
        )
