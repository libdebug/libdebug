#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Francesco Panebianco, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.data.memory_map import MemoryMap
    from libdebug.state.thread_context import ThreadContext


class Aarch64StackUnwinder(StackUnwindingManager):
    """Class that provides stack unwinding for the AArch64 architecture."""

    def unwind(self: Aarch64StackUnwinder, target: ThreadContext) -> list:
        """Unwind the stack of a process.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            list: A list of return addresses.
        """
        assert hasattr(target.regs, "pc")

        frame_pointer = target.regs.x29

        vmaps = target._internal_debugger.debugging_interface.maps()
        initial_link_register = None

        try:
            initial_link_register = self.get_return_address(target, vmaps)
        except ValueError:
            liblog.warning(
                "Failed to get the return address. Check stack frame registers (e.g., base pointer). The stack trace may be incomplete.",
            )

        stack_trace = [target.regs.pc, initial_link_register] if initial_link_register else [target.regs.pc]

        # Follow the frame chain
        while frame_pointer:
            try:
                link_register = int.from_bytes(target.memory[frame_pointer + 8, 8, "absolute"], byteorder="little")
                frame_pointer = int.from_bytes(target.memory[frame_pointer, 8, "absolute"], byteorder="little")

                if not any(vmap.start <= link_register < vmap.end for vmap in vmaps):
                    break

                # Leaf functions don't set the previous stack frame pointer
                # But they set the link register to the return address
                # Non-leaf functions set both
                if initial_link_register and link_register == initial_link_register:
                    initial_link_register = None
                    continue

                stack_trace.append(link_register)
            except (OSError, ValueError):
                break

        return stack_trace

    def get_return_address(self: Aarch64StackUnwinder, target: ThreadContext, vmaps: list[MemoryMap]) -> int:
        """Get the return address of the current function.

        Args:
            target (ThreadContext): The target ThreadContext.
            vmaps (list[MemoryMap]): The memory maps of the process.

        Returns:
            int: The return address.
        """
        return_address = target.regs.x30

        if not any(vmap.start <= return_address < vmap.end for vmap in vmaps):
            raise ValueError("Return address not in any valid memory map")

        return return_address
