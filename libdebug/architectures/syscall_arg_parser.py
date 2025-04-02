#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.aarch64.aarch64_syscall_arg_parser import (
    AARCH64_SYSCALL_PARSER_MAP,
)
from libdebug.architectures.amd64.amd64_syscall_arg_parser import (
    AMD64_SYSCALL_PARSER_MAP,
)
from libdebug.architectures.i386.i386_syscall_arg_parser import (
    I386_SYSCALL_PARSER_MAP,
)


def parse_syscall_arg(
    architecture: str,
    syscall_number: int,
    syscall_arg_index: int,
    syscall_arg_value: int,
) -> str:
    """Parse the syscall arguments based on the syscall number and argument name.

    Args:
        architecture (str): The architecture of the binary (e.g., "amd64", "i386", "aarch64").
        syscall_number (int): The syscall number.
        syscall_arg_index (int): The syscall argument index."
        syscall_arg_value (int): The syscall argument value."

    Returns:
        str: The parsed syscall argument value.
    """
    if architecture == "amd64":
        syscall_parser_map = AMD64_SYSCALL_PARSER_MAP
    elif architecture == "i386":
        syscall_parser_map = I386_SYSCALL_PARSER_MAP
    elif architecture == "aarch64":
        syscall_parser_map = AARCH64_SYSCALL_PARSER_MAP
    else:
        raise ValueError(f"Unsupported architecture: {architecture}")

    # Get the syscall parser for the given syscall number
    sys_args = syscall_parser_map.get(syscall_number)

    if sys_args is None:
        return hex(syscall_arg_value)

    # Get the syscall argument parser for the given syscall argument index
    sys_arg_alternatives = sys_args.get(syscall_arg_index)

    if sys_arg_alternatives is None:
        return hex(syscall_arg_value)

    # If the syscall argument value is 0, return the value corresponding to 0 if it exists
    if syscall_arg_value == 0:
        if sys_arg_alternatives.get(0) is not None:
            return sys_arg_alternatives[0]
        else:
            return hex(syscall_arg_value)

    # Retrieve the parsing mode (default is OR)
    parsing_mode = sys_arg_alternatives.get("parsing_mode", "or")

    if parsing_mode == "or":
        # At this point than one mnemonic is likely
        out_mnemonic = ""

        masked_bits = 0x000000000000000000

        for mnemonic_mask, mnemonic in sys_arg_alternatives.items():

            if not isinstance(mnemonic_mask, int):
                # If the mask is not an integer, skip it
                # it's string metadata
                continue

            # Check if the syscall argument value matches the mnemonic mask
            if mnemonic_mask & syscall_arg_value:
                if len(out_mnemonic) == 0:
                    out_mnemonic = mnemonic
                else:
                    out_mnemonic += f" | {mnemonic}"

                masked_bits |= mnemonic_mask

        # If not all bits are masked, add the remaining bits to the mnemonic in OR
        if ~masked_bits & syscall_arg_value != 0:
            out_mnemonic += f" | {syscall_arg_value & ~masked_bits:#08x}"
    elif parsing_mode == "sequential":
        candidate = sys_arg_alternatives.get(syscall_arg_value)

        if candidate is not None:
            out_mnemonic = candidate
    elif parsing_mode == "mixed":
        out_mnemonic = ""

        # Handle "sequential_flags" if present
        sequential_flags = sys_arg_alternatives.get("sequential_flags", {})
        candidate = sequential_flags.get(syscall_arg_value)
        if candidate is not None:
            out_mnemonic = candidate

        # Handle "or_flags" if present
        or_flags = sys_arg_alternatives.get("or_flags", {})
        if or_flags:
            masked_bits = 0x000000000000000000
            or_mnemonic = ""

            for mnemonic_mask, mnemonic in or_flags.items():
                if mnemonic_mask & syscall_arg_value:
                    if len(or_mnemonic) == 0:
                        or_mnemonic = mnemonic
                    else:
                        or_mnemonic += f" | {mnemonic}"

                    masked_bits |= mnemonic_mask

            # If not all bits are masked, add the remaining bits to the mnemonic in OR
            if ~masked_bits & syscall_arg_value != 0:
                or_mnemonic += f" | {syscall_arg_value & ~masked_bits:#08x}"

            # Combine sequential and OR mnemonics if both exist
            if len(out_mnemonic) > 0 and len(or_mnemonic) > 0:
                out_mnemonic += f" | {or_mnemonic}"
            elif len(or_mnemonic) > 0:
                out_mnemonic = or_mnemonic

    if len(out_mnemonic) == 0:
        return hex(syscall_arg_value)

    return out_mnemonic
