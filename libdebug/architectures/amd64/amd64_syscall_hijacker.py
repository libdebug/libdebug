#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import Any, Callable
from libdebug.state.thread_context import ThreadContext
from libdebug.architectures.syscall_hijacking_manager import SyscallHijackingManager


class Amd64SyscallHijacker(SyscallHijackingManager):
    """Class that provides syscall hijacking for the x86_64 architecture."""

    def create_hijacker(
        self, new_syscall: int, **kwargs: Any
    ) -> Callable[[ThreadContext, int], None]:
        """
        Create a new hijacker for the given syscall.

        Args:
            new_syscall (int): The new syscall number.
            **kwargs: The keyword arguments.
        """

        def hijack_on_enter_wrapper(d: ThreadContext, _: int):
            """Wrapper for the hijack_on_enter method."""
            self._hijack_on_enter(d, new_syscall, **kwargs)

        return hijack_on_enter_wrapper

    def _hijack_on_enter(
        self, d: ThreadContext, new_syscall: int, **kwargs: Any
    ) -> None:
        """
        Hijack the syscall on enter.

        Args:
            d (ThreadContext): The target ThreadContext.
            new_syscall (int): The new syscall number.
            **kwargs: The keyword arguments.
        """

        allowed_args = {
            "syscall_number",
            "syscall_arg0",
            "syscall_arg1",
            "syscall_arg2",
            "syscall_arg3",
            "syscall_arg4",
            "syscall_arg5",
        }

        if set(kwargs) - allowed_args:
            raise ValueError("Invalid keyword arguments in syscall hijack")

        d.syscall_number = new_syscall
        if "syscall_arg0" in kwargs:
            d.syscall_arg0 = kwargs.get("syscall_arg0", False)
        if "syscall_arg1" in kwargs:
            d.syscall_arg1 = kwargs.get("syscall_arg1", False)
        if "syscall_arg2" in kwargs:
            d.syscall_arg2 = kwargs.get("syscall_arg2", False)
        if "syscall_arg3" in kwargs:
            d.syscall_arg3 = kwargs.get("syscall_arg3", False)
        if "syscall_arg4" in kwargs:
            d.syscall_arg4 = kwargs.get("syscall_arg4", False)
        if "syscall_arg5" in kwargs:
            d.syscall_arg5 = kwargs.get("syscall_arg5", False)
