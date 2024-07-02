#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


class SyscallHijackingManager(ABC):
    """An architecture-independent interface for syscall hijacking."""

    @abstractmethod
    def create_hijacker(
        self: SyscallHijackingManager,
        new_syscall: int,
        **kwargs: int,
    ) -> Callable[[ThreadContext, int], None]:
        """Create a new hijacker for the given syscall."""

    @abstractmethod
    def _hijack_on_enter(self: SyscallHijackingManager, d: ThreadContext, new_syscall: int, **kwargs: int) -> None:
        """Hijack the syscall on enter."""
