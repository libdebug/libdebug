#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.syscall_arg_parser import syscall_arg_parser
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.gnu_constants import GnuConstants
from libdebug.utils.libcontext import libcontext
from libdebug.utils.platform_utils import get_platform_gp_register_size
from libdebug.utils.syscall_utils import (
    resolve_syscall_arguments,
    resolve_syscall_name,
)

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

MAX_STR_SHOW_LEN = 32


def negate_value(value: int, word_size: int) -> int:
    """Negate a value.

    Args:
        value (int): the value.
        word_size (int): the word size.

    Returns:
        int: the negated value.
    """
    return (1 << word_size * 8) - value


def numeric_or_mnemonic(
    value: int,
    mnemonic_dict: dict,
    equality: bool,
    negate_search: bool,
    word_size: int | None = None,
) -> str:
    """Return the mnemonic of a value if it is present in the mnemonic dictionary.

    Args:
        value (int): the value.
        mnemonic_dict (dict): the mnemonic dictionary.
        equality (bool): if True, check for equality of the value, otherwise mask values in OR.
        negate_search (bool): if True, negate the value to query the mnemonic. Valid if equality is True.
        word_size (int | None): the word size. Defaults to None.

    Returns:
        str: the mnemonic.
    """
    numeric_str = f"{value:#x}"

    if not libcontext.parse_pprint_constants:
        return numeric_str

    # Parse exact match
    if equality:
        mnemonic_val = negate_value(value, word_size) if negate_search else value
        mnemonic = mnemonic_dict.get(mnemonic_val)
        mnemonic = mnemonic["short_name"] if mnemonic is not None else numeric_str
    # Parse bitwise OR
    else:
        mnemonics_list = []
        for key, mnemonic in mnemonic_dict.items():
            if key & value:
                mnemonics_list.append(mnemonic["short_name"])
        mnemonic = " | ".join(mnemonics_list) if mnemonics_list else numeric_str

    return mnemonic


def parse_syscall_arg(t: ThreadContext, sycall_num: int, arg_num: int, arg_val: int, is_string: bool = False) -> str:
    """Parse a syscall argument.

    Args:
        t (ThreadContext): the thread context.
        sycall_num (int): the syscall number.
        arg_num (int): the argument number.
        arg_val (int): the argument value.
        is_string (bool): if True, the argument is a string. Defaults to False.
    """
    if not libcontext.parse_pprint_constants:
        return f"{arg_val:#x}"
    elif is_string:
        string_content = ""

        curr_char = ""
        cursor = arg_val

        while curr_char != "\0":
            string_content += curr_char
            curr_char = chr(int.from_bytes(t.memory[cursor, 1, "absolute"]))
            cursor += 1

            if cursor - arg_val > MAX_STR_SHOW_LEN:
                string_content += f"...[truncated] ({MAX_STR_SHOW_LEN} bytes)"
                break

        return (
            f'"{string_content}" ({arg_val:#x})'.replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            .replace("\b", "\\b")
            .replace("\f", "\\f")
            .replace("\a", "\\a")
            .replace("\v", "\\v")
        )
    else:
        return syscall_arg_parser(
            t._internal_debugger.arch,
            sycall_num,
            arg_num,
            arg_val,
        )


def pprint_on_enter(t: ThreadContext, syscall_number: int, **kwargs: int) -> None:
    """Function that will be called when a syscall is entered in pretty print mode.

    Args:
        t (ThreadContext): the thread context.
        syscall_number (int): the syscall number.
        **kwargs (bool): the keyword arguments.
    """
    syscall_name = resolve_syscall_name(t._internal_debugger.arch, syscall_number)
    syscall_args = resolve_syscall_arguments(t._internal_debugger.arch, syscall_number)

    values = [
        t.syscall_arg0,
        t.syscall_arg1,
        t.syscall_arg2,
        t.syscall_arg3,
        t.syscall_arg4,
        t.syscall_arg5,
    ]

    values_str = []

    # Parse the arguments
    for arg_index, value, name in zip(range(len(values)), values, syscall_args, strict=False):
        is_string = "char" in name

        values_str.append(parse_syscall_arg(t, syscall_number, arg_index, value, is_string))

    # Print the thread id
    header = f"{ANSIColors.BOLD}{t.tid}{ANSIColors.RESET} "

    if "old_args" in kwargs:
        old_args = kwargs["old_args"]
        old_args_str = []

        # Parse the old arguments
        for arg_index, value, name in zip(range(len(old_args)), old_args, syscall_args, strict=False):
            is_string = "char" in name

            old_args_str[arg_index] = parse_syscall_arg(t, syscall_number, arg_index, value, is_string)

        entries = [
            f"{arg} = {ANSIColors.BRIGHT_YELLOW}{value}{ANSIColors.DEFAULT_COLOR}"
            if old_value == value
            else f"{arg} = {ANSIColors.STRIKE}{ANSIColors.BRIGHT_YELLOW}{old_value}{ANSIColors.RESET} {ANSIColors.BRIGHT_YELLOW}0x{value:x}{ANSIColors.DEFAULT_COLOR}"
            for arg, value, old_value in zip(syscall_args, values_str, old_args_str, strict=False)
            if arg is not None
        ]
    else:
        entries = [
            f"{arg} = {ANSIColors.BRIGHT_YELLOW}{value}{ANSIColors.DEFAULT_COLOR}"
            for arg, value in zip(syscall_args, values_str, strict=False)
            if arg is not None
        ]

    hijacked = kwargs.get("hijacked", False)
    user_handled = kwargs.get("callback", False)
    hijacker = kwargs.get("hijacker", None)
    if hijacked:
        print(
            f"{header}{ANSIColors.RED}(hijacked) {ANSIColors.STRIKE}{ANSIColors.BLUE}{syscall_name}{ANSIColors.DEFAULT_COLOR}({', '.join(entries)}){ANSIColors.RESET}",
        )
    elif user_handled:
        print(
            f"{header}{ANSIColors.RED}(callback) {ANSIColors.BLUE}{syscall_name}{ANSIColors.DEFAULT_COLOR}({', '.join(entries)}) = ",
            end="",
        )
    elif hijacker:
        print(
            f"{header}{ANSIColors.RED}(executed) {ANSIColors.BLUE}{syscall_name}{ANSIColors.DEFAULT_COLOR}({', '.join(entries)}) = ",
            end="",
        )
    else:
        print(
            f"{header}{ANSIColors.BLUE}{syscall_name}{ANSIColors.DEFAULT_COLOR}({', '.join(entries)}) = ",
            end="",
        )


def pprint_on_exit(t: ThreadContext, syscall_return: int | tuple[int, int]) -> None:
    """Function that will be called when a syscall is exited in pretty print mode.

    Args:
        t (ThreadContext): the thread context.
        syscall_return (int | list[int]): the syscall return value.
    """
    word_size = get_platform_gp_register_size(t.debugger.arch)

    if isinstance(syscall_return, tuple):
        real_retval = numeric_or_mnemonic(
            syscall_return[0],
            GnuConstants.ERRNOS,
            equality=True,
            negate_search=True,
            word_size=word_size,
        )
        changed_retval = numeric_or_mnemonic(
            syscall_return[1],
            GnuConstants.ERRNOS,
            equality=True,
            negate_search=True,
            word_size=word_size,
        )

        print(
            f"{ANSIColors.YELLOW}{ANSIColors.STRIKE}{real_retval}{ANSIColors.RESET} {ANSIColors.YELLOW}{changed_retval}{ANSIColors.RESET}",
        )
    else:
        retval = numeric_or_mnemonic(syscall_return, GnuConstants.ERRNOS, equality=True, negate_search=True, word_size=word_size)
        print(f"{ANSIColors.YELLOW}{retval}{ANSIColors.RESET}")
