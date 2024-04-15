#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.state.thread_context import ThreadContext
from libdebug.architectures.amd64.amd64_thread_context import ThreadContextAmd64
from libdebug.architectures.i386.i386_thread_context import ThreadContextI386
from libdebug.architectures.i386.i386_over_amd64_thread_context import (
    ThreadContextI386OverAmd64,
)
from libdebug.architectures.aarch64.aarch64_thread_context import ThreadContextAarch64
from libdebug.utils.libcontext import libcontext


def provide_thread_context(arch: str, thread_id: int) -> ThreadContext:
    platform = libcontext.platform

    match (arch, platform):
        case ("amd64", "x86_64"):
            return ThreadContextAmd64(thread_id)
        case ("i386", "i686"):
            return ThreadContextI386(thread_id)
        case ("i386", "x86_64"):
            return ThreadContextI386OverAmd64(thread_id)
        case ("aarch64", "aarch64"):
            return ThreadContextAarch64(thread_id)
        case _:
            raise NotImplementedError(
                f"Architecture {arch} on machine {platform} not available."
            )
