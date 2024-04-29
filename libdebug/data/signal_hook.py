#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


@dataclass
class SignalHook:
    """A hook for a signal in the target process.

    Attributes:
        signal_number (int): The signal number to hook.
        pass_to_process (bool): Whether to pass the signal to the process or not.
        callback (Callable[[ThreadContext, int], None]): The callback defined by the user to execute when the signal is received.
        enabled (bool): Whether the hook is enabled or not.
        hook_hijack (bool): Whether to execute the hook/hijack of the new signal after an hijack or not.
        hit_count (int): The number of times the hook has been hit."""

    signal_number: int
    callback: Callable[["ThreadContext", int], None]
    hook_hijack: bool = True
    enabled: bool = True
    hit_count: int = 0

    def enable(self) -> None:
        """Enable the signal hook."""
        from libdebug.state.debugging_context import provide_context

        if provide_context(self).running:
            raise RuntimeError(
                "Cannot enable a signal hook while the target process is running."
            )

        self.enabled = True

    def disable(self) -> None:
        """Disable the signal hook."""
        from libdebug.state.debugging_context import provide_context

        if provide_context(self).running:
            raise RuntimeError(
                "Cannot disable a signal hook while the target process is running."
            )

        self.enabled = False

    def __hash__(self) -> int:
        return hash(self.signal_number)
