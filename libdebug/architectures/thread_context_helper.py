#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.aarch64.aarch64_thread_context import Aarch64ThreadContext
from libdebug.architectures.amd64.amd64_thread_context import Amd64ThreadContext
from libdebug.architectures.amd64.compat.i386_over_amd64_thread_context import (
    I386OverAMD64ThreadContext,
)
from libdebug.architectures.i386.i386_thread_context import I386ThreadContext
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.libcontext import libcontext


def thread_context_class_provider(
    architecture: str,
) -> type[ThreadContext]:
    """Returns the class of the thread context to be used by the `_InternalDebugger` class."""
    match architecture:
        case "amd64":
            return Amd64ThreadContext
        case "aarch64":
            return Aarch64ThreadContext
        case "i386":
            if libcontext.platform == "amd64":
                return I386OverAMD64ThreadContext
            else:
                return I386ThreadContext
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
