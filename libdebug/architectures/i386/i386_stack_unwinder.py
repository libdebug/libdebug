#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.state.internal_thread_context import InternalThreadContext


class I386StackUnwinder(StackUnwindingManager):
    """Class that provides stack unwinding for the i386 architecture."""

    def unwind(self: I386StackUnwinder, target: InternalThreadContext) -> list:
        """Unwind the stack of a process.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            list: A list of return addresses.
        """
        assert hasattr(target.regs, "eip")
        assert hasattr(target.regs, "ebp")

        current_ebp = target.regs.ebp
        stack_trace = [target.regs.eip]

        vmaps = target._internal_debugger.debugging_interface.get_maps()

        while current_ebp:
            try:
                # Read the return address
                return_address = int.from_bytes(target.memory[current_ebp + 4, 4], byteorder="little")

                if not any(vmap.start <= return_address < vmap.end for vmap in vmaps):
                    break

                # Read the previous ebp and set it as the current one
                current_ebp = int.from_bytes(target.memory[current_ebp, 4], byteorder="little")

                stack_trace.append(return_address)
            except (OSError, ValueError):
                break

        # If we are in the prologue of a function, we need to get the return address from the stack
        # using a slightly more complex method
        try:
            first_return_address = self.get_return_address(target, vmaps)

            if len(stack_trace) > 1:
                if first_return_address != stack_trace[1]:
                    stack_trace.insert(1, first_return_address)
            else:
                stack_trace.append(first_return_address)
        except (OSError, ValueError):
            liblog.WARNING(
                "Failed to get the return address from the stack. Check stack frame registers (e.g., base pointer). The stack trace may be incomplete.",
            )

        return stack_trace

    def get_return_address(self: I386StackUnwinder, target: InternalThreadContext, vmaps: MemoryMapList[MemoryMap]) -> int:
        """Get the return address of the current function.

        Args:
            target (ThreadContext): The target ThreadContext.
            vmaps (list[MemoryMap]): The memory maps of the process.

        Returns:
            int: The return address.
        """
        instruction_window = target.memory[target.regs.eip, 4]

        # Check if the instruction window is a function preamble and handle each case
        return_address = None

        if self._preamble_state(instruction_window) == 0:
            return_address = target.memory[target.regs.ebp + 4, 4]
        elif self._preamble_state(instruction_window) == 1:
            return_address = target.memory[target.regs.esp, 4]
        else:
            return_address = target.memory[target.regs.esp + 4, 4]

        return_address = int.from_bytes(return_address, byteorder="little")

        if not vmaps.filter(return_address):
            raise ValueError("Return address is not in any memory map.")

        return return_address

    def _preamble_state(self: I386StackUnwinder, instruction_window: bytes) -> int:
        """Check if the instruction window is a function preamble and, if so, at what stage.

        Args:
            instruction_window (bytes): The instruction window.

        Returns:
            int: 0 if not a preamble, 1 if ebp has not been pushed yet, 2 otherwise
        """
        preamble_state = 0

        # endbr32 and push ebp
        if b"\xf3\x0f\x1e\xfb" in instruction_window or b"\x55" in instruction_window:
            preamble_state = 1

        # mov ebp, esp
        elif b"\x89\xe5" in instruction_window:
            preamble_state = 2

        return preamble_state
