#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.data.register_holder import RegisterHolder

if TYPE_CHECKING:
    from libdebug.state.internal_thread_context import InternalThreadContext


@dataclass
class PtraceRegisterHolder(RegisterHolder):
    """An abstract class that holds the state of the registers of a process, providing setters and getters for them.

    Intended for use with the Ptrace debugging backend.
    """

    register_file: object
    """The register file of the target process, as returned by ptrace."""

    fp_register_file: object
    """The floating-point register file of the target process, as returned by ptrace."""

    def poll(self: PtraceRegisterHolder, target: InternalThreadContext) -> None:
        """Poll the register values from the specified target."""
        raise NotImplementedError("Do not call this method.")

    def flush(self: PtraceRegisterHolder, source: InternalThreadContext) -> None:
        """Flush the register values from the specified source."""
        raise NotImplementedError("Do not call this method.")
