#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.architectures.call_utilities_manager import CallUtilitiesManager


class Aarch64CallUtilities(CallUtilitiesManager):
    """Class that provides call utilities for the AArch64 architecture."""

    def is_call(self: Aarch64CallUtilities, opcode_window: bytes) -> bool:
        """Check if the current instruction is a call instruction."""
        # Check for BL instruction
        if (opcode_window[3] & 0xFC) == 0x94:
            return True

        # Check for BLR instruction
        if opcode_window[3] == 0xD6 and (opcode_window[2] & 0x3F) == 0x3F:
            return True

        return False

    def compute_call_skip(self: Aarch64CallUtilities, opcode_window: bytes) -> int:
        """Compute the instruction size of the current call instruction."""
        # Check for BL instruction
        if self.is_call(opcode_window):
            return 4

        return 0

    def get_call_and_skip_amount(self: Aarch64CallUtilities, opcode_window: bytes) -> tuple[bool, int]:
        """Get the call instruction and the amount of bytes to skip."""
        skip = self.compute_call_skip(opcode_window)
        return skip != 0, skip
