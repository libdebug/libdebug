#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from collections.abc import Callable

from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    Amd64PtraceRegisterHolder,
)
from libdebug.data.register_holder import RegisterHolder
from libdebug.utils.libcontext import libcontext


def register_holder_provider(
    register_file: object,
    _: Callable[[], object] | None = None,
    __: Callable[[object], None] | None = None,
) -> RegisterHolder:
    """Returns an instance of the register holder to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64PtraceRegisterHolder(register_file)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
