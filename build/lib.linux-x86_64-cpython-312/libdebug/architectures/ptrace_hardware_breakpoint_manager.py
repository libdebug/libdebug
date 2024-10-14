#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.data.breakpoint import Breakpoint
    from libdebug.state.thread_context import ThreadContext


class PtraceHardwareBreakpointManager(ABC):
    """An architecture-independent interface for managing hardware breakpoints.

    Attributes:
        thread (ThreadContext): The target thread.
        peek_user (callable): A function that reads a number of bytes from the target thread registers.
        poke_user (callable): A function that writes a number of bytes to the target thread registers.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self: PtraceHardwareBreakpointManager,
        thread: ThreadContext,
        peek_user: Callable[[int, int], int],
        poke_user: Callable[[int, int, int], None],
    ) -> None:
        """Initializes the hardware breakpoint manager."""
        self.thread = thread
        self.peek_user = peek_user
        self.poke_user = poke_user
        self.breakpoint_count = 0

    @abstractmethod
    def install_breakpoint(self: PtraceHardwareBreakpointManager, bp: Breakpoint) -> None:
        """Installs a hardware breakpoint at the provided location."""

    @abstractmethod
    def remove_breakpoint(self: PtraceHardwareBreakpointManager, bp: Breakpoint) -> None:
        """Removes a hardware breakpoint at the provided location."""

    @abstractmethod
    def available_breakpoints(self: PtraceHardwareBreakpointManager) -> int:
        """Returns the number of available hardware breakpoint registers."""

    @abstractmethod
    def is_watchpoint_hit(self: PtraceHardwareBreakpointManager) -> Breakpoint | None:
        """Checks if a watchpoint has been hit.

        Returns:
            Breakpoint | None: The watchpoint that has been hit, or None if no watchpoint has been hit.
        """
