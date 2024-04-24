#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class SyscallHijackingManager:
    """
    An architecture-independent interface for syscall hijacking.
    """

    def create_hijacker(
        self, new_syscall: int, **kwargs: Any
    ) -> Callable[["ThreadContext", int], None]:
        """
        Create a new hijacker for the given syscall.
        """ 
        pass

    def hijack_on_enter(self, d: "ThreadContext", new_syscall: int, **kwargs: Any):
        """
        Unwind the stack of the target process.
        """
        pass
