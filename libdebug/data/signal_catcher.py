#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


@dataclass
class SignalCatcher:
    """Catch a signal raised by the target process.

    Attributes:
        signal_number (int): The signal number to catch.
        callback (Callable[[ThreadContext, CaughtSignal], None]): The callback defined by the user to execute when the
        signal is caught.
        recursive (bool): Whether, when the signal is hijacked with another one, the signal catcher associated with the
        new signal should be considered as well. Defaults to False.
        enabled (bool): Whether the signal will be caught or not.
        hit_count (int): The number of times the signal has been caught.
    """

    signal_number: int
    callback: Callable[[ThreadContext, SignalCatcher], None]
    recursive: bool = True
    enabled: bool = True
    hit_count: int = 0

    def enable(self: SignalCatcher) -> None:
        """Enable the signal catcher."""
        provide_internal_debugger(self)._ensure_process_stopped()
        self.enabled = True

    def disable(self: SignalCatcher) -> None:
        """Disable the signal catcher."""
        provide_internal_debugger(self)._ensure_process_stopped()
        self.enabled = False

    def hit_on(self: SignalCatcher, thread_context: ThreadContext) -> bool:
        """Returns whether the signal catcher has been hit on the given thread context."""
        return self.enabled and thread_context._signal_number == self.signal_number

    def __hash__(self: SignalCatcher) -> int:
        """Return the hash of the signal catcher, based just on the signal number."""
        return hash(self.signal_number)
