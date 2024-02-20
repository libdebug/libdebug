#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini
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

from libdebug.architectures.register_holder import RegisterHolder
from libdebug.state.process_context import ProcessContext
from libdebug.utils.debugging_utils import resolve_address_in_maps


class ThreadContext:
    """
    This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack.
    """

    registers: RegisterHolder
    """The register holder object. It provides access to the thread's registers."""

    thread_id: int
    """The thread's ID."""

    process_context: ProcessContext
    """The process context object."""

    def __init__(self, thread_id: int, process_context: ProcessContext):
        self.thread_id = thread_id
        self.process_context = process_context
        self.interface = process_context.interface

    @staticmethod
    def new(process_context: ProcessContext, thread_id: int = None):
        """Creates a new thread context object.

        Args:
            process_context (ProcessContext): The process context object.
            thread_id (int, optional): The thread's ID. Defaults to None.

        Returns:
            ThreadContext: The thread context object.
        """
        if thread_id is None:
            # If no thread ID is specified, we assume the main thread which has tid = pid
            thread_id = process_context.process_id

        return ThreadContext(thread_id, process_context)

    @property
    def running(self):
        """True if and only if the thread is currently running."""
        # TODO we might handle this differently in the future, where we can interrupt a single thread
        # and/or have a single thread running
        return self.process_context.running

    def interrupt(self):
        """Synchronously interrupts the thread."""
        # TODO we might handle this differently in the future, where we can interrupt a single thread
        # and/or have a single thread running
        self.process_context.interrupt()

    def _poll_registers(self):
        """Updates the register values."""
        self.registers = self.interface.get_register_holder(self.thread_id)
        if self.registers:
            self.registers.apply_on(self, ThreadContext)

    def _flush_registers(self):
        self.registers.flush(self)

    def backtrace(self):
        """Returns the current backtrace of the thread."""
        backtrace = self.stack_unwinding.unwind(self)
        return list(
            map(
                lambda x: resolve_address_in_maps(x, self.process_context.maps()),
                backtrace,
            )
        )
