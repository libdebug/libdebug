#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.interfaces.interfaces import AvailableInterfaces
from libdebug.ptrace.ptrace_interface import PtraceInterface


def provide_debugging_interface(
    interface: AvailableInterfaces = AvailableInterfaces.PTRACE,
) -> DebuggingInterface:
    """Returns an instance of the debugging interface to be used by the `_InternalDebugger` class."""
    match interface:
        case AvailableInterfaces.PTRACE:
            return PtraceInterface()
        case _:
            raise NotImplementedError(f"Interface {interface} not available.")
