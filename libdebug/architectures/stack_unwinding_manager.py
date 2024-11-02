#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.memory_map import MemoryMap
    from libdebug.state.internal_thread_context import InternalThreadContext


class StackUnwindingManager(ABC):
    """An architecture-independent interface for stack unwinding."""

    @abstractmethod
    def unwind(self: StackUnwindingManager, target: InternalThreadContext) -> list:
        """Unwind the stack of the target process."""

    @abstractmethod
    def get_return_address(self: StackUnwindingManager, target: InternalThreadContext, vmaps: list[MemoryMap]) -> int:
        """Get the return address of the current function."""
