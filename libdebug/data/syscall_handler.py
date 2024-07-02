#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


@dataclass
class SyscallHandler:
    """Handle a syscall executed by the target process.

    Attributes:
        syscall_number (int): The syscall number to handle.
        on_enter_user (Callable[[ThreadContext, int], None]): The callback defined by the user to execute when the
        syscall is entered.
        on_exit_user (Callable[[ThreadContext, int], None]): The callback defined by the user to execute when the
        syscall is exited.
        on_enter_pprint (Callable[[ThreadContext, int], None]): The callback defined by the pretty print to execute when
        the syscall is entered.
        on_exit_pprint (Callable[[ThreadContext, int], None]): The callback defined by the pretty print to execute when
        the syscall is exited.
        recursive (bool): Whether, when the syscall is hijacked with another one, the syscall handler associated with
        the new syscall should be considered as well. Defaults to False.
        enabled (bool): Whether the syscall will be handled or not.
        hit_count (int): The number of times the syscall has been handled.
    """

    syscall_number: int
    on_enter_user: Callable[[ThreadContext, int], None]
    on_exit_user: Callable[[ThreadContext, int], None]
    on_enter_pprint: Callable[[ThreadContext, int, Any], None]
    on_exit_pprint: Callable[[int | tuple[int, int]], None]
    recursive: bool = False
    enabled: bool = True
    hit_count: int = 0

    _has_entered: bool = False
    _skip_exit: bool = False

    def enable(self: SyscallHandler) -> None:
        """Handle the syscall."""
        provide_internal_debugger(self)._ensure_process_stopped()
        self.enabled = True
        self._has_entered = False

    def disable(self: SyscallHandler) -> None:
        """Unhandle the syscall."""
        provide_internal_debugger(self)._ensure_process_stopped()
        self.enabled = False
        self._has_entered = False

    def hit_on_enter(self: SyscallHandler, thread_context: ThreadContext) -> bool:
        """Returns whether the syscall handler has been hit during the syscall entry on the given thread context."""
        return self.enabled and thread_context.syscall_number == self.syscall_number and self._has_entered

    def hit_on_exit(self: SyscallHandler, thread_context: ThreadContext) -> bool:
        """Returns whether the syscall handler has been hit during the syscall exit on the given thread context."""
        return self.enabled and thread_context.syscall_number == self.syscall_number and not self._has_entered

    def __hash__(self: SyscallHandler) -> int:
        """Return the hash of the syscall handler, based just on the syscall number."""
        return hash(self.syscall_number)
