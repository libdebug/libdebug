#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.debugger.mixins.base import EngineBoundMixin
from libdebug.utils.oop.alias import check_aliased_property

if TYPE_CHECKING:
    from libdebug.data.registers import Registers


class ThreadStateMixin(EngineBoundMixin):
    """Helpers to inspect or mutate the main thread state."""

    @property
    def instruction_pointer(self: ThreadStateMixin) -> int:
        """Get the main thread's instruction pointer."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].instruction_pointer

    @instruction_pointer.setter
    def instruction_pointer(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's instruction pointer."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].instruction_pointer = value

    @property
    def syscall_arg0(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 0."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg0

    @syscall_arg0.setter
    def syscall_arg0(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 0."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg0 = value

    @property
    def syscall_arg1(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 1."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg1

    @syscall_arg1.setter
    def syscall_arg1(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 1."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg1 = value

    @property
    def syscall_arg2(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 2."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg2

    @syscall_arg2.setter
    def syscall_arg2(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 2."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg2 = value

    @property
    def syscall_arg3(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 3."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg3

    @syscall_arg3.setter
    def syscall_arg3(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 3."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg3 = value

    @property
    def syscall_arg4(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 4."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg4

    @syscall_arg4.setter
    def syscall_arg4(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 4."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg4 = value

    @property
    def syscall_arg5(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall argument 5."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_arg5

    @syscall_arg5.setter
    def syscall_arg5(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall argument 5."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_arg5 = value

    @property
    def syscall_number(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall number."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_number

    @syscall_number.setter
    def syscall_number(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall number."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_number = value

    @property
    def syscall_return(self: ThreadStateMixin) -> int:
        """Get the main thread's syscall return value."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].syscall_return

    @syscall_return.setter
    def syscall_return(self: ThreadStateMixin, value: int) -> None:
        """Set the main thread's syscall return value."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].syscall_return = value

    @property
    def regs(self: ThreadStateMixin) -> Registers:
        """Get the main thread's registers."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self._internal_debugger._ensure_process_stopped_regs()
        return self.threads[0].regs

    @property
    def dead(self: ThreadStateMixin) -> bool:
        """Whether the process is dead."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].dead

    @property
    def zombie(self: ThreadStateMixin) -> None:
        """Whether the main thread is a zombie."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].zombie

    @check_aliased_property("tid")
    def thread_id(self: ThreadStateMixin) -> int:
        """The thread ID of the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].tid

    @property
    def tid(self: ThreadStateMixin) -> int:
        """Alias for the `thread_id` property.

        The thread ID of the main thread.
        """
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].tid

    @property
    def saved_ip(self: ThreadStateMixin) -> int:
        """Get the saved instruction pointer of the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].saved_ip

    @property
    def exit_code(self: ThreadStateMixin) -> int | None:
        """The main thread's exit code."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].exit_code

    @property
    def exit_signal(self: ThreadStateMixin) -> str | None:
        """The main thread's exit signal."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].exit_signal

    @property
    def signal(self: ThreadStateMixin) -> str | None:
        """The signal to be forwarded to the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].signal

    @signal.setter
    def signal(self: ThreadStateMixin, signal: str | int) -> None:
        """Set the signal to forward to the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].signal = signal

    @property
    def signal_number(self: ThreadStateMixin) -> int | None:
        """The signal number to be forwarded to the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].signal_number

    def backtrace(self: ThreadStateMixin, as_symbols: bool = False) -> list:
        """Returns the current backtrace of the main thread.

        Args:
            as_symbols (bool, optional): Whether to return the backtrace as symbols
        """
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        return self.threads[0].backtrace(as_symbols)
