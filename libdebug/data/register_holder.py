#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.state.internal_thread_context import InternalThreadContext


class RegisterHolder(ABC):
    """An abstract class that holds the state of the registers of a process, providing setters and getters for them."""

    @abstractmethod
    def apply_on_thread(self: RegisterHolder, target: InternalThreadContext, target_class: type) -> None:
        """Applies the current register values to the specified thread target.

        Args:
            target (InternalThreadContext): The object to which the register values should be applied.
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
    def poll(self: RegisterHolder, target: InternalThreadContext) -> None:
        """Polls the register values from the specified target.

        Args:
            target (InternalThreadContext): The object from which the register values should be polled.
        """

    @abstractmethod
    def flush(self: RegisterHolder, source: InternalThreadContext) -> None:
        """Flushes the register values from the specified source.

        Args:
            source (InternalThreadContext): The object from which the register values should be flushed.
        """

    @abstractmethod
    def provide_regs(self: RegisterHolder) -> list[str]:
        """Provide the list of registers, excluding the vector and fp registers."""

    @abstractmethod
    def provide_vector_fp_regs(self: RegisterHolder) -> list[tuple[str]]:
        """Provide the list of vector and floating point registers."""

    @abstractmethod
    def provide_special_regs(self: RegisterHolder) -> list[str]:
        """Provide the list of special registers, which are not intended for general-purpose use."""
