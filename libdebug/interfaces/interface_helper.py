#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.interfaces.interfaces import BackendInterface
from libdebug.interfaces.ptrace_interface import PtraceInterface
from libdebug.qemu_stub.qemu_stub_interface import QemuStubInterface


def provide_debugging_interface(
    interface: BackendInterface = BackendInterface.PTRACE,
) -> DebuggingInterface:
    """Returns an instance of the debugging interface to be used by the `_InternalDebugger` class."""
    match interface:
        case BackendInterface.PTRACE:
            return PtraceInterface()
        case BackendInterface.QEMU_STUB:
            return QemuStubInterface()
        case _:
            raise NotImplementedError(f"Interface {interface} not available.")
