#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager
from libdebug.state.debugging_context import provide_context

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
            print(f'Currently unwinding stack at RBP: {hex(current_rbp)}')
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

    def get_return_address(self, target: "ThreadContext") -> int:
        """
        Get the return address of the current function.

        Args:
            target (ThreadContext): The target ThreadContext.

        Returns:
            int: The return address.
        """

        # Set the thread to background mode to avoid deadlock
        target._in_background_op = True

        instruction_window = target.memory[target.rip, 4]

        # Check if the instruction window is a function preamble and handle each case
        return_address = None

        if self._preamble_state(instruction_window) == 0:
            return_address = target.memory[target.rbp + 8, 4]
        elif self._preamble_state(instruction_window) == 1:
            return_address = target.memory[target.rsp, 4]
        else:
            return_address = target.memory[target.rsp + 8, 4]
        
        return_address = int.from_bytes(return_address, byteorder="little")

        # Restore the thread to normal mode
        target._in_background_op = False

        return return_address

    def _preamble_state(self, instruction_window: bytes) -> int:
        """
        Check if the instruction window is a function preamble and if so at what stage.

        Args:
            instruction_window (bytes): The instruction window.

        Returns:
            int: 0 if not a preamble, 1 if rbp has not been pushed yet, 2 otherwise
        """

        preambleState = 0

        # endbr64
        if b'\xf3\x0f\x1e\xfa' in instruction_window:
            preambleState = 1
        # push rbp
        elif b'\x55' in instruction_window:
            preambleState = 1
        # mov rbp, rsp
        elif b'\x48\x89\xe5' in instruction_window:
            preambleState = 2

        return preambleState
