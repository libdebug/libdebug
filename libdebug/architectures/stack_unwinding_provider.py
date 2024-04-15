#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_stack_unwinder import (
    Amd64StackUnwinder,
)
from libdebug.architectures.i386.i386_stack_unwinder import (
    I386StackUnwinder,
)
from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager

_amd64_stack_unwinder = Amd64StackUnwinder()
_i386_stack_unwinder = I386StackUnwinder()


def stack_unwinding_provider(arch: str) -> StackUnwindingManager:
    """Returns an instance of the stack unwinding provider to be used by the `_InternalDebugger` class."""

    match arch:
        case "amd64":
            return _amd64_stack_unwinder
        case "i386":
            return _i386_stack_unwinder
        case _:
            raise NotImplementedError(f"Architecture {arch} not available.")
