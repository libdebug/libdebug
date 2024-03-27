#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_stack_unwinder import (
    Amd64StackUnwinder,
)
from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager
from libdebug.utils.libcontext import libcontext

_amd64_stack_unwinder = Amd64StackUnwinder()


def stack_unwinding_provider() -> StackUnwindingManager:
    """Returns an instance of the stack unwinding provider to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return _amd64_stack_unwinder
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
