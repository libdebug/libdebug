#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod


class CallUtilitiesManager(ABC):
    """An architecture-independent interface for call instruction utilities."""

    @abstractmethod
    def is_call(self: CallUtilitiesManager, opcode_window: bytes) -> bool:
        """Check if the current instruction is a call instruction."""

    @abstractmethod
    def compute_call_skip(self: CallUtilitiesManager, opcode_window: bytes) -> int:
        """Compute the address where to skip after the current call instruction."""

    @abstractmethod
    def get_call_and_skip_amount(self: CallUtilitiesManager, opcode_window: bytes) -> tuple[bool, int]:
        """Check if the current instruction is a call instruction and compute the instruction size."""

    @abstractmethod
    def get_syscall_instruction(self: CallUtilitiesManager) -> bytes:
        """Return the bytes of the syscall instruction."""
