#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


def validate_breakpoint_i386(bp: Breakpoint) -> None:
    """Validate a hardware breakpoint for the i386 architecture."""
    if bp.condition not in ["w", "rw", "x"]:
        raise ValueError("Invalid condition for watchpoints. Supported conditions are 'w', 'rw', 'x'.")

    if bp.length not in [1, 2, 4, 8]:
        raise ValueError("Invalid length for watchpoints. Supported lengths are 1, 2, 4, 8.")
