#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Francesco Panebianco, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager

if TYPE_CHECKING:
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
        initial_link_register = target.regs.x30
        stack_trace = [target.regs.pc, initial_link_register]

        vmaps = target._internal_debugger.debugging_interface.maps()

        # Follow the frame chain
        while frame_pointer:
            try:
                link_register = int.from_bytes(target.memory[frame_pointer + 8, 8], byteorder="little")
                frame_pointer = int.from_bytes(target.memory[frame_pointer, 8], byteorder="little")

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

    def get_return_address(self: Aarch64StackUnwinder, target: ThreadContext) -> int:
        """Get the return address of the current function.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            int: The return address.
        """
        return target.regs.x30
