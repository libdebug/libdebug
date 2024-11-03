#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler


class ResumeContext:
    """A class representing the context of the resume decision."""

    def __init__(self: ResumeContext) -> None:
        """Initializes the ResumeContext."""
        self.resume: bool = True
        self.force_interrupt: bool = False
        self.is_a_step: bool = False
        self.is_startup: bool = False
        self.is_a_step_finish: bool = False
        self.block_on_signal: bool = False
        self.threads_with_signals_to_forward: list[int] = []
        self.event_type: dict[int, EventType] = {}
        self.event_hit_ref: dict[int, Breakpoint | SignalCatcher | SyscallHandler] = {}

    def clear(self: ResumeContext) -> None:
        """Clears the context."""
        self.resume = True
        self.force_interrupt = False
        self.is_a_step = False
        self.is_startup = False
        self.is_a_step_finish = False
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
                    event_str += f"{event} on thread {tid}."

        return event_str


class EventType:
    """A class representing the type of event that caused the resume decision."""

    UNKNOWN = "Unknown Event"
    BREAKPOINT = "Breakpoint"
    SYSCALL = "Syscall"
    SIGNAL = "Signal"
    USER_INTERRUPT = "User Interrupt"
    STEP = "Step"
    STARTUP = "Process Startup"
    FINISH = "Finish"
