#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


@dataclass
class SyscallHook:
    """A hook for a syscall in the target process.

    Attributes:
        syscall_number (int): The syscall number to hook.
        on_enter_user (Callable[[ThreadContext, int], None]): The callback defined by the user to execute when the syscall is entered.
        on_exit_user (Callable[[ThreadContext, int], None]): The callback defined by the user to execute when the syscall is exited.
        on_enter_pprint (Callable[[ThreadContext, int], None]): The callback defined by the pretty print to execute when the syscall is entered.
        on_exit_pprint (Callable[[ThreadContext, int], None]): The callback defined by the pretty print to execute when the syscall is exited.
    """

    syscall_number: int
    on_enter_user: Callable[[ThreadContext, int], None]
    on_exit_user: Callable[[ThreadContext, int], None]
    on_enter_pprint: Callable[[ThreadContext, int], None]
    on_exit_pprint: Callable[[ThreadContext, int], None]
    hook_hijack: bool = True
    enabled: bool = True
    hit_count: int = 0

    _has_entered: bool = False

    def enable(self) -> None:
        """Enable the syscall hook."""
        from libdebug.state.debugging_context import provide_context

        if provide_context(self).running:
            raise RuntimeError(
                "Cannot enable a syscall hook while the target process is running."
            )

        self.enabled = True
        self._has_entered = False

    def disable(self) -> None:
        """Disable the syscall hook."""
        from libdebug.state.debugging_context import provide_context

        if provide_context(self).running:
            raise RuntimeError(
                "Cannot disable a syscall hook while the target process is running."
            )

        self.enabled = False
        self._has_entered = False

    def __hash__(self) -> int:
        return hash(self.syscall_number)
