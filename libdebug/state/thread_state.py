#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class ThreadState:
    """A class representing the state of a thread."""

    running: bool
    """A boolean indicating if the thread is running."""

    scheduled: bool
    """A boolean indicating if the thread should run."""

    dead: bool
    """A boolean indicating if the thread is dead."""

    exit_code: int | None
    """The thread's exit code."""

    exit_signal: int | None
    """The thread's exit signal."""

    signal_number: int
    """"The signal to forward to the thread."""

    def __init__(self: ThreadState) -> None:
        """Initializes the ThreadState."""
        self.running = False
        self.scheduled = False
        self.dead = False
        self.exit_code = None
        self.exit_signal = None
        self.signal_number = 0

    def clear(self: ThreadState) -> None:
        """Clears the thread state."""
        self.running = False
        self.scheduled = False
        self.dead = False
        self.exit_code = None
        self.exit_signal = None
        self.signal_number = 0
