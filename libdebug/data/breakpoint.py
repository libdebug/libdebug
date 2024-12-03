#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


@dataclass
class Breakpoint:
    """A breakpoint in the target process.

    Attributes:
        address (int): The address of the breakpoint in the target process.
        symbol (str): The symbol, if available, of the breakpoint in the target process.
        thread_id (int): The thread ID of the thread for which the breakpoint should be set. Defaults to -1, which means all threads.
        hit_count (int): The number of times this specific breakpoint has been hit.
        hardware (bool): Whether the breakpoint is a hardware breakpoint or not.
        callback (Callable[[ThreadContext, Breakpoint], None]): The callback defined by the user to execute when the breakpoint is hit.
        condition (str): The breakpoint condition. Available values are "X", "W", "RW". Supported only for hardware breakpoints.
        length (int): The length of the breakpoint area. Supported only for hardware breakpoints.
        enabled (bool): Whether the breakpoint is enabled or not.
    """

    address: int = 0
    symbol: str = ""
    thread_id: int = -1
    hit_count: int = 0
    hardware: bool = False
    callback: None | Callable[[ThreadContext, Breakpoint], None] = None
    condition: str = "x"
    length: int = 1
    enabled: bool = True

    _linked_thread_ids: list[int] = field(default_factory=list)
    # The thread ID that hit the breakpoint

    _disabled_for_step: bool = False
    _changed: bool = False

    def enable(self: Breakpoint) -> None:
        """Enable the breakpoint."""
        provide_internal_debugger(self).ensure_process_stopped()
        self.enabled = True
        self._changed = True

    def disable(self: Breakpoint) -> None:
        """Disable the breakpoint."""
        provide_internal_debugger(self).ensure_process_stopped()
        self.enabled = False
        self._changed = True

    def hit_on(self: Breakpoint, thread_context: ThreadContext) -> bool:
        """Returns whether the breakpoint has been hit on the given thread context."""
        if not self.enabled:
            return False

        internal_debugger = provide_internal_debugger(self)
        internal_debugger.ensure_process_stopped()
        events = internal_debugger.resume_context.event_hit_ref.get(thread_context.thread_id, [])
        return self in events

    def __hash__(self: Breakpoint) -> int:
        """Hash the breakpoint by its address, so that it can be used in sets and maps correctly."""
        return hash(self.address)

    def __eq__(self: Breakpoint, other: object) -> bool:
        """Check if two breakpoints are equal."""
        return id(self) == id(other)
