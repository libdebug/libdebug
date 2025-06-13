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
        return bool(opcode_window[3] == 214 and opcode_window[2] & 63 == 63)

    def compute_call_skip(self: Aarch64CallUtilities, opcode_window: bytes) -> int:
        """Compute the instruction size of the current call instruction."""
        # Check for BL instruction
        if self.is_call(opcode_window):
            return 4

        return 0

    def get_call_and_skip_amount(self: Aarch64CallUtilities, opcode_window: bytes) -> tuple[bool, int]:
        """Check if the current instruction is a call instruction and compute the instruction size."""
        skip = self.compute_call_skip(opcode_window)
        return skip != 0, skip

    def get_syscall_instruction(self: CallUtilitiesManager) -> bytes:
        """Return the bytes of the syscall instruction."""
        return b"\x1f\x20\x03\xd5\x01\x00\x00\xD4\x1f\x20\x03\xd5" # SVC #0 + NOPs
