#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.aarch64.aarch64_breakpoint_validator import validate_breakpoint_aarch64
from libdebug.architectures.amd64.amd64_breakpoint_validator import validate_breakpoint_amd64

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint

def validate_hardware_breakpoint(arch: str, bp: Breakpoint) -> None:
    """Validate a hardware breakpoint for the specified architecture."""
    if arch == "aarch64":
        validate_breakpoint_aarch64(bp)
    elif arch == "amd64":
        validate_breakpoint_amd64(bp)
    else:
        raise ValueError(f"Architecture {arch} not supported")
