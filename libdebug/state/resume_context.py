#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class ResumeContext:
    """A class representing the context of the resume decision."""

    def __init__(self: ResumeContext) -> None:
        """Initializes the ResumeContext."""
        self.resume: bool = True
        self.force_interrupt: bool = False
        self.is_a_step: bool = False
        self.is_startup: bool = False
        self.block_on_signal: bool = False
        self.threads_with_signals_to_forward: list[int] = []

    def clear(self: ResumeContext) -> None:
        """Clears the context."""
        self.resume = True
        self.force_interrupt = False
        self.is_a_step = False
        self.is_startup = False
        self.block_on_signal = False
        self.threads_with_signals_to_forward.clear()
