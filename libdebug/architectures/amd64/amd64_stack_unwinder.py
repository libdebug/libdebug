#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

class Amd64StackUnwinder(StackUnwindingManager):
    """Class that provides stack unwinding for the x86_64 architecture."""

    def unwind(self: Amd64StackUnwinder, target: ThreadContext) -> list:
        """Unwind the stack of a process.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            list: A list of return addresses.
        """
        assert hasattr(target.regs, "rip")
        assert hasattr(target.regs, "rbp")

        current_rbp = target.regs.rbp
        stack_trace = [target.regs.rip]

        vmaps = target._internal_debugger.debugging_interface.maps()

        while current_rbp:
            try:
                # Read the return address
                return_address = int.from_bytes(target.memory[current_rbp + 8, 8], byteorder="little")

                if not any(vmap.start <= return_address < vmap.end for vmap in vmaps):
                    break

                # Read the previous rbp and set it as the current one
                current_rbp = int.from_bytes(target.memory[current_rbp, 8], byteorder="little")

                stack_trace.append(return_address)
            except (OSError, ValueError):
                break

        return stack_trace

    def get_return_address(self: Amd64StackUnwinder, target: ThreadContext) -> int:
        """Get the return address of the current function.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            int: The return address.
        """
        instruction_window = target.memory[target.regs.rip, 4]

        # Check if the instruction window is a function preamble and handle each case
        return_address = None

        if self._preamble_state(instruction_window) == 0:
            return_address = target.memory[target.regs.rbp + 8, 8]
        elif self._preamble_state(instruction_window) == 1:
            return_address = target.memory[target.regs.rsp, 8]
        else:
            return_address = target.memory[target.regs.rsp + 8, 8]

        return int.from_bytes(return_address, byteorder="little")

    def _preamble_state(self: Amd64StackUnwinder, instruction_window: bytes) -> int:
        """Check if the instruction window is a function preamble and if so at what stage.

        Args:
            instruction_window (bytes): The instruction window.

        Returns:
            int: 0 if not a preamble, 1 if rbp has not been pushed yet, 2 otherwise
        """
        preamble_state = 0

        # endbr64 and push rbp
        if b"\xf3\x0f\x1e\xfa" in instruction_window or b"\x55" in instruction_window:
            preamble_state = 1
        # mov rbp, rsp
        elif b"\x48\x89\xe5" in instruction_window:
            preamble_state = 2

        return preamble_state
