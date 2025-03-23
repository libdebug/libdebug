#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.architectures.call_utilities_manager import CallUtilitiesManager


class I386CallUtilities(CallUtilitiesManager):
    """Class that provides call utilities for the i386 architecture."""

    def is_call(self: I386CallUtilities, opcode_window: bytes) -> bool:
        """Check if the current instruction is a call instruction."""
        # Check for direct CALL (E8 xx xx xx xx)
        if opcode_window[0] == 0xE8:
            return True

        # Check for indirect CALL using ModR/M (FF /2)
        if opcode_window[0] == 0xFF:
            # Extract ModR/M byte
            modRM = opcode_window[1]
            reg = (modRM >> 3) & 0x07

            if reg == 2:
                return True

        return False

    def compute_call_skip(self: I386CallUtilities, opcode_window: bytes) -> int:
        """Compute the instruction size of the current call instruction."""
        # Check for direct CALL (E8 xx xx xx xx)
        if opcode_window[0] == 0xE8:
            return 5

        # Check for indirect CALL using ModR/M (FF /2)
        if opcode_window[0] == 0xFF:
            # Extract ModR/M byte
            modRM = opcode_window[1]
            mod = (modRM >> 6) & 0x03
            reg = (modRM >> 3) & 0x07

            if reg == 2:
                if mod == 0:
                    if (modRM & 0x07) == 4:
                        return 3 + (4 if opcode_window[2] == 0x25 else 0)
                    elif (modRM & 0x07) == 5:
                        return 6
                    return 2
                elif mod == 1:
                    return 3
                elif mod == 2:
                    return 6
                elif mod == 3:
                    return 2

        return 0

    def get_call_and_skip_amount(self: I386CallUtilities, opcode_window: bytes) -> tuple[bool, int]:
        skip = self.compute_call_skip(opcode_window)
        return skip != 0, skip

    def get_syscall_instruction(self: CallUtilitiesManager) -> bytes:
        """Return the bytes of the syscall instruction."""
        return b"\xCD\x80" # int 0x80
