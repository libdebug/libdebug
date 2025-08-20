#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.state.thread_context import ThreadContext


@dataclass(eq=False)
class Breakpoint:
    """A breakpoint in the target process.

    Attributes:
        address (int): The address of the breakpoint in the target process.
        symbol (str): The symbol, if available, of the breakpoint in the target process.
        hit_count (int): The number of times this specific breakpoint has been hit.
        hardware (bool): Whether the breakpoint is a hardware breakpoint or not.
        callback (Callable[[ThreadContext, Breakpoint], None]): The callback defined by the user to execute when the breakpoint is hit.
        condition (str): The breakpoint condition. Available values are "X", "W", "RW". Supported only for hardware breakpoints.
        length (int): The length of the breakpoint area. Supported only for hardware breakpoints.
        enabled (bool): Whether the breakpoint is enabled or not.
    """

    address: int = 0
    symbol: str = ""
    hit_count: int = 0
    hardware: bool = False
    callback: None | Callable[[ThreadContext, Breakpoint], None] = None
    condition: str = "x"
    length: int = 1

    _enabled: bool = field(default=True, init=False, repr=False)
    _linked_thread_ids: list[int] = field(default_factory=list, init=False, repr=False)
    _disabled_for_step: bool = field(default=False, init=False, repr=False)
    _changed: bool = field(default=False, init=False, repr=False)
    _internal_debugger: InternalDebugger = field(default=None, init=True, repr=False)

    @property
    def enabled(self: Breakpoint) -> bool:
        """Whether the breakpoint is enabled or not."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled

    @enabled.setter
    def enabled(self: Breakpoint, value: bool) -> None:
        """Set the enabled state of the breakpoint."""
        self._internal_debugger._ensure_process_stopped()
        self._enabled = value
        self._changed = True

    def enable(self: Breakpoint) -> None:
        """Enable the breakpoint."""
        self.enabled = True

    def disable(self: Breakpoint) -> None:
        """Disable the breakpoint."""
        self.enabled = False

    def hit_on(self: Breakpoint, thread_context: ThreadContext) -> bool:
        """Returns whether the breakpoint has been hit on the given thread context."""
        self._internal_debugger._ensure_process_stopped()

        if not self._enabled:
            return False

        return self._internal_debugger.resume_context.event_hit_ref.get(thread_context.thread_id) == self
