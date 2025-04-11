#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
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
        callback (Callable[[ThreadContext, CaughtSignal], None]): The callback defined by the user to execute when the signal is caught.
        recursive (bool): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.
        enabled (bool): Whether the signal will be caught or not.
        hit_count (int): The number of times the signal has been caught.
    """

    signal_number: int
    callback: Callable[[ThreadContext, SignalCatcher], None]
    recursive: bool = True
    hit_count: int = 0
    _enabled: bool = True

    @property
    def enabled(self: SignalCatcher) -> bool:
        """Return whether the signal catcher is enabled or not."""
        provide_internal_debugger(self)._ensure_process_stopped()
        return self._enabled

    @enabled.setter
    def enabled(self: SignalCatcher, value: bool) -> None:
        """Set whether the signal catcher is enabled or not."""
        provide_internal_debugger(self)._ensure_process_stopped()
        self._enabled = value

    def enable(self: SignalCatcher) -> None:
        """Enable the signal catcher."""
        self.enabled = True

    def disable(self: SignalCatcher) -> None:
        """Disable the signal catcher."""
        self.enabled = False

    def hit_on(self: SignalCatcher, thread_context: ThreadContext) -> bool:
        """Returns whether the signal catcher has been hit on the given thread context."""
        provide_internal_debugger(self)._ensure_process_stopped()
        return self._enabled and thread_context.signal_number == self.signal_number

    def __hash__(self: SignalCatcher) -> int:
        """Hash the signal catcher object by its memory address, so that it can be used in sets and dicts correctly."""
        return hash(id(self))

    def __eq__(self: SignalCatcher, other: object) -> bool:
        """Check if two catchers are equal."""
        return id(self) == id(other)
