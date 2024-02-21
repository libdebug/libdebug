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

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.data.register_holder import RegisterHolder
from libdebug.state.debugging_context import debugging_context
from libdebug.utils.debugging_utils import resolve_address_in_maps


class ThreadContext:
    """
    This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack.
    """

    registers: RegisterHolder
    """The register holder object. It provides access to the thread's registers."""

    thread_id: int
    """The thread's ID."""

    _needs_poll_registers: bool = True
    """Whether the registers need to be polled."""

    _needs_sigcont: bool = False
    """Whether the thread needs to be continued after a signal stop."""

    def __init__(self, thread_id: int):
        self.thread_id = thread_id

    @staticmethod
    def new(thread_id: int = None):
        """Creates a new thread context object.

        Args:
            thread_id (int, optional): The thread's ID. Defaults to None.

        Returns:
            ThreadContext: The thread context object.
        """
        if thread_id is None:
            # If no thread ID is specified, we assume the main thread which has tid = pid
            thread_id = debugging_context.process_id

        return ThreadContext(thread_id)

    def _poll_registers(self):
        """Updates the register values."""
        if not self._needs_poll_registers:
            self._needs_poll_registers = True
            return

        self.registers = debugging_context.debugging_interface.get_register_holder(
            self.thread_id
        )
        if self.registers:
            self.registers.apply_on(self, ThreadContext)

    def _flush_registers(self):
        if self.registers:
            self.registers.flush(self)

    def backtrace(self):
        """Returns the current backtrace of the thread."""
        stack_unwinder = stack_unwinding_provider()
        backtrace = stack_unwinder.unwind(self)
        return list(
            map(
                lambda x: resolve_address_in_maps(
                    x, debugging_context.debugging_interface.maps()
                ),
                backtrace,
            )
        )
