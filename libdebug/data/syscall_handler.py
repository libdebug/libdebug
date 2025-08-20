#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.state.thread_context import ThreadContext


@dataclass(eq=False)
class SyscallHandler:
    """Handle a syscall executed by the target process.

    Attributes:
        syscall_number (int): The syscall number to handle.
        on_enter_user (Callable[[ThreadContext, SyscallHandler], None]): The callback defined by the user to execute when the syscall is entered.
        on_exit_user (Callable[[ThreadContext, SyscallHandler], None]): The callback defined by the user to execute when the syscall is exited.
        on_enter_pprint (Callable[[ThreadContext, int, Any], None]): The callback defined by the pretty print to execute when the syscall is entered.
        on_exit_pprint (Callable[[int | tuple[int, int]], None]): The callback defined by the pretty print to execute when the syscall is exited.
        recursive (bool): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.
        enabled (bool): Whether the syscall will be handled or not.
        hit_count (int): The number of times the syscall has been handled.
    """

    syscall_number: int
    on_enter_user: Callable[[ThreadContext, SyscallHandler], None]
    on_exit_user: Callable[[ThreadContext, SyscallHandler], None]
    on_enter_pprint: Callable[[ThreadContext, int, Any], None] = field(repr=False)
    on_exit_pprint: Callable[[int | tuple[int, int]], None] = field(repr=False)
    recursive: bool = False
    hit_count: int = 0

    _enabled: bool = field(default=True, init=False, repr=True)
    _has_entered: bool = field(default=False, init=False, repr=False)
    _skip_exit: bool = field(default=False, init=False, repr=False)
    _internal_debugger: InternalDebugger = field(default=None, init=True, repr=False)

    @property
    def enabled(self: SyscallHandler) -> bool:
        """Returns whether the syscall handler is enabled or not."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled

    @enabled.setter
    def enabled(self: SyscallHandler, value: bool) -> None:
        """Sets whether the syscall handler is enabled or not."""
        self._internal_debugger._ensure_process_stopped()
        self._enabled = value
        self._has_entered = False

    def enable(self: SyscallHandler) -> None:
        """Handle the syscall."""
        self.enabled = True

    def disable(self: SyscallHandler) -> None:
        """Unhandle the syscall."""
        self.enabled = False

    def hit_on(self: SyscallHandler, thread_context: ThreadContext) -> bool:
        """Returns whether the syscall handler has been hit on the given thread context."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled and thread_context.syscall_number == self.syscall_number

    def hit_on_enter(self: SyscallHandler, thread_context: ThreadContext) -> bool:
        """Returns whether the syscall handler has been hit during the syscall entry on the given thread context."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled and thread_context.syscall_number == self.syscall_number and self._has_entered

    def hit_on_exit(self: SyscallHandler, thread_context: ThreadContext) -> bool:
        """Returns whether the syscall handler has been hit during the syscall exit on the given thread context."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled and thread_context.syscall_number == self.syscall_number and not self._has_entered
