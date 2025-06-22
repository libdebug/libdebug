#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


def validate_breakpoint_amd64(bp: Breakpoint) -> None:
    """Validate a hardware breakpoint for the AMD64 architecture."""
    if bp.condition not in ["w", "rw", "x"]:
        raise ValueError("Invalid condition for watchpoints. Supported conditions are 'w', 'rw', 'x'.")

    if bp.condition == "x" and bp.length != 1:
        # See Intel® 64 and IA-32 Architectures Software Developer's Manual
        # Volume 3B: System Programming Guide, Part 2
        # CHAPTER 18 DEBUGGING AND PERFORMANCE MONITORING
        # 18.2.5 Breakpoint Field Recognition
        liblog.warning(
            f"Condition 'x' is set for a breakpoint with length {bp.length}. "
            "This may lead to architecturally undefined behaviour due to hardware limitations. "
            "Forcing length to 1 byte.",
        )
        bp.length = 1
    elif bp.length not in [1, 2, 4, 8]:
        raise ValueError("Invalid length for watchpoints. Supported lengths are 1, 2, 4, 8.")

    if bp.address % bp.length != 0 and bp.condition != "x":
        # See Intel® 64 and IA-32 Architectures Software Developer's Manual
        # Volume 3B: System Programming Guide, Part 2
        # CHAPTER 18 DEBUGGING AND PERFORMANCE MONITORING
        # 18.2.5 Breakpoint Field Recognition
        raise ValueError(
            f"Address {bp.address:#x} is not aligned to its length ({bp.length}). "
            "Read- and write-type hardware breakpoints must be aligned to their length. "
            "This is a hardware limitation of the x86 architecture, where not aligning the address "
            "may lead to undefined behaviour. "
            "Some debuggers work around it by transparently realigning the address—"
            "either by extending the range where possible or by using multiple hardware "
            "breakpoint registers. "
            "libdebug deliberately does not do this leaving the decision to the you. ",
        )
