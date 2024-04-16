#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import Callable

from libdebug.architectures.aarch64.aarch64_ptrace_register_holder import (
    Aarch64PtraceRegisterHolder,
)
from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    Amd64PtraceRegisterHolder,
)
from libdebug.architectures.i386.i386_over_am64_ptrace_register_holder import (
    I386POverAmd64traceRegisterHolder,
)
from libdebug.architectures.i386.i386_ptrace_register_holder import (
    I386PtraceRegisterHolder,
)
from libdebug.data.register_holder import RegisterHolder
from libdebug.utils.libcontext import libcontext


def register_holder_provider(
    architecture: str,
    register_file: object,
    getter: Callable[[], object] | None = None,
    setter: Callable[[object], None] | None = None,
) -> RegisterHolder:
    """Returns an instance of the register holder to be used by the `_InternalDebugger` class."""
    platform = libcontext.platform

    match (architecture, platform):
        case "amd64", "x86_64":
            return Amd64PtraceRegisterHolder(register_file)
        case "i386", "x86_64":
            return I386POverAmd64traceRegisterHolder(register_file)
        case "i386", "i686":
            return I386PtraceRegisterHolder(register_file)
        case "aarch64", "aarch64":
            return Aarch64PtraceRegisterHolder(register_file)
        case _:
            raise NotImplementedError(
                f"Architecture {architecture} on platform {platform} not available."
            )
