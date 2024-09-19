#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


def validate_breakpoint_aarch64(bp: Breakpoint) -> None:
    """Validate a hardware breakpoint for the AARCH64 architecture."""
    if bp.condition not in ["r", "w", "rw", "x"]:
        raise ValueError("Invalid condition for watchpoints. Supported conditions are 'r', 'w', 'rw', 'x'.")

    if not (1 <= bp.length <= 8):
        raise ValueError("Invalid length for watchpoints. Supported lengths are between 1 and 8.")

    if bp.condition != "x" and bp.address & 0x7:
        raise ValueError("Watchpoint address must be aligned to 8 bytes on aarch64. This is a kernel limitation.")
