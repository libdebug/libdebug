#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.data.event_type import EventType
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.state.thread_context import ThreadContext


@dataclass(eq=False)
class EventHook:
    """An event hook for debugger events.

    Attributes:
        event (str): The name of the event.
        callback (Callable[..., None]): The callback to execute when the event is triggered.
        post_hook (bool): Whether the hook is a post-hook or pre-hook.
        hit_count (int): The number of times this event hook has been triggered.
    """

    event: EventType = field(default=None)
    callback: Callable[[ThreadContext, EventHook], None] | None = field(default=None)
    hit_count: int = field(default=0, init=False)

    _enabled: bool = field(default=True, init=False, repr=False)
    _post_hook: bool = field(default=False, init=True, repr=False)
    _internal_debugger: InternalDebugger = field(default=None, init=True, repr=False)

    @property
    def enabled(self: EventHook) -> bool:
        """Whether the event hook is enabled or not."""
        self._internal_debugger._ensure_process_stopped()
        return self._enabled

    @enabled.setter
    def enabled(self: EventHook, value: bool) -> None:
        """Set the enabled state of the event hook."""
        if not isinstance(value, bool):
            raise TypeError("enabled must be a boolean value")
        self._internal_debugger._ensure_process_stopped()
        self._enabled = value

    @property
    def is_post_hook(self: EventHook) -> bool:
        """Whether the event hook is a post-hook or pre-hook."""
        self._internal_debugger._ensure_process_stopped()
        return self._post_hook

    @is_post_hook.setter
    def is_post_hook(self: EventHook, value: bool) -> None:
        """Set whether the event hook is a post-hook or pre-hook."""
        if not isinstance(value, bool):
            raise TypeError("post_hook must be a boolean value")
        self._internal_debugger._ensure_process_stopped()
        self._post_hook = value

    def enable(self: EventHook) -> None:
        """Enable the event hook."""
        self.enabled = True

    def disable(self: EventHook) -> None:
        """Disable the event hook."""
        self.enabled = False

    def __repr__(self: EventHook) -> str:
        """Return a string representation of the EventHook."""
        return f"EventHook(type={self.event_type.name}, is_post_hook={self.is_post_hook}, enabled={self.enabled}, hit_count={self.hit_count})"
