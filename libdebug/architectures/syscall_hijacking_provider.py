#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_syscall_hijacker import (
    Amd64SyscallHijacker,
)
from libdebug.architectures.syscall_hijacking_manager import SyscallHijackingManager
from libdebug.utils.libcontext import libcontext

_amd64_syscall_hijacker = Amd64SyscallHijacker()


def syscall_hijacking_provider() -> SyscallHijackingManager:
    """Returns an instance of the syscall hijacking provider to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return _amd64_syscall_hijacker
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
