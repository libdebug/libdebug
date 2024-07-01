#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class RegisterHolder(ABC):
    """An abstract class that holds the state of the registers of a process, providing setters and getters for them."""

    @abstractmethod
    def apply_on_thread(self: RegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Applies the current register values to the specified thread target.

        Args:
            target (ThreadContext): The object to which the register values should be applied.
            target_class (type): The class of the target object, needed to set the attributes.
        """

    @abstractmethod
    def apply_on_regs(self: RegisterHolder, target: object, target_class: type) -> None:
        """Applies the current register values to the specified regs target.

        Args:
            target (object): The object to which the register values should be applied.
            target_class (type): The class of the target object, needed to set the attributes.
        """

    @abstractmethod
    def poll(self: RegisterHolder, target: ThreadContext) -> None:
        """Polls the register values from the specified target.

        Args:
            target (ThreadContext): The object from which the register values should be polled.
        """

    @abstractmethod
    def flush(self: RegisterHolder, source: ThreadContext) -> None:
        """Flushes the register values from the specified source.

        Args:
            source (ThreadContext): The object from which the register values should be flushed.
        """
