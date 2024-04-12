#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.utils.syscall_utils import (
    resolve_syscall_name,
    resolve_syscall_number,
    resolve_syscall_arguments,
    get_all_syscall_numbers,
)
from libdebug.state.thread_context import ThreadContext


def install_pretty_print_syscall_hook(
    d: ThreadContext, syscalls: list[str | int] = None, exclude: list[str | int] = None
):
    """Installs a syscall hook that will pretty print the syscall arguments and return value."""

    def on_enter_syscall(d, syscall_number):
        syscall_name = resolve_syscall_name(syscall_number)
        syscall_args = resolve_syscall_arguments(syscall_number)

        values = [
            d.syscall_arg0,
            d.syscall_arg1,
            d.syscall_arg2,
            d.syscall_arg3,
            d.syscall_arg4,
            d.syscall_arg5,
        ]

        entries = [
            f"{arg} = 0x{value:x}"
            for arg, value in zip(syscall_args, values)
            if arg is not None
        ]

        print(f"{syscall_name}({', '.join(entries)}) = ", end="")

    def on_exit_syscall(d, _):
        print(f"0x{d.syscall_return:x}")

    if syscalls is None:
        syscalls = get_all_syscall_numbers()

    syscall_numbers = []

    for syscall in syscalls:
        if isinstance(syscall, str):
            syscall_numbers.append(resolve_syscall_number(syscall))
        else:
            syscall_numbers.append(syscall)

    if exclude is not None:
        for excluded in exclude:
            if isinstance(excluded, str):
                excluded = resolve_syscall_number(excluded)

            syscall_numbers.remove(excluded)

    for syscall_number in syscall_numbers:
        d.hook_syscall(syscall_number, on_enter_syscall, on_exit_syscall)
