#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class Amd64StackUnwinder(StackUnwindingManager):
    """
    Class that provides stack unwinding for the x86_64 architecture.
    """

    def unwind(self, target: "ThreadContext") -> list:
        """
        Unwind the stack of a process.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            list: A list of return addresses.
        """

        assert hasattr(target, "rip")
        assert hasattr(target, "rbp")

        current_rbp = target.rbp
        stack_trace = [target.rip]

        while current_rbp:
            try:
                # Read the return address
                return_address = int.from_bytes(
                    target.memory[current_rbp + 8, 8], byteorder="little"
                )

                # Read the previous rbp and set it as the current one
                current_rbp = int.from_bytes(
                    target.memory[current_rbp, 8], byteorder="little"
                )

                stack_trace.append(return_address)
            except OSError:
                break

        return stack_trace
