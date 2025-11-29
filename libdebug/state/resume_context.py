#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from libdebug.data.event_type import EventType

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


@dataclass(eq=False)
class ResumeContext:
    """Represents the context used to decide whether execution should resume."""

    resume: bool = True
    force_interrupt: bool = False
    is_a_step: bool = False
    is_startup: bool = False
    block_on_signal: bool = False
    threads_with_signals_to_forward: list[int] = field(default_factory=list)
    event_type: dict[int, EventType] = field(default_factory=dict)
    event_hit_ref: dict[int, Breakpoint] = field(default_factory=dict)
    is_in_callback: bool = False

    def clear(self: ResumeContext) -> None:
        """Clears the context."""
        self.resume = True
        self.force_interrupt = False
        self.is_a_step = False
        self.is_startup = False
        self.block_on_signal = False
        self.threads_with_signals_to_forward.clear()
        self.event_type.clear()
        self.event_hit_ref.clear()

    def get_event_type(self: ResumeContext) -> str:
        """Returns the event type to be printed."""
        event_str = ""
        if self.event_type:
            for tid, event in self.event_type.items():
                if event == EventType.BREAKPOINT:
                    hit_ref = self.event_hit_ref[tid]
                    if hit_ref.condition != "x":
                        event_str += (
                            f"Watchpoint at {hit_ref.address:#x} with condition {hit_ref.condition} on thread {tid}."
                        )
                    else:
                        event_str += f"Breakpoint at {hit_ref.address:#x} on thread {tid}."
                elif event == EventType.SYSCALL:
                    hit_ref = self.event_hit_ref[tid]
                    event_str += f"Syscall {hit_ref.syscall_number} on thread {tid}."
                elif event == EventType.SIGNAL:
                    hit_ref = self.event_hit_ref[tid]
                    event_str += f"Signal {hit_ref.signal} on thread {tid}."
                else:
                    event_str += f"{event.value} on thread {tid}."

        return event_str
