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
from libdebug.utils.parsing_utils import or_parse, sequential_parse


def syscall_arg_parser(
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

    default_val = f"{syscall_arg_value:#x}"

    # Get the syscall parser map for the given syscall number
    specific_syscall_map = syscall_parser_map.get(syscall_number)

    # If the syscall has not defined constants, return the default value
    if specific_syscall_map is None:
        return default_val

    specific_arg_map = specific_syscall_map.get(syscall_arg_index)

    # If the syscall argument has not defined constants, return the default value
    if specific_arg_map is None:
        return default_val

    # Retrieve the parsing mode (default is OR)
    parsing_mode = specific_arg_map.get("parsing_mode", "or")

    if parsing_mode == "or":
        out_mnemonic = or_parse(specific_arg_map, syscall_arg_value)
    elif parsing_mode == "sequential":
        out_mnemonic = sequential_parse(specific_arg_map, syscall_arg_value)
    elif parsing_mode == "mixed":
        out_mnemonic = ""

        # Handle "or_flags" if present
        or_flags = specific_arg_map.get("or_flags", {})
        if or_flags:
            masked_bits = 0x000000000000000000
            or_mnemonic = ""

            for mnemonic_mask, mnemonic in or_flags.items():
                if mnemonic_mask == 0 and syscall_arg_value != 0:
                    # If the mask is 0 and the syscall argument value is not 0, skip it
                    continue

                if mnemonic_mask & syscall_arg_value == mnemonic_mask:
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

        # Handle "sequential_flags" if present
        sequential_flags = specific_arg_map.get("sequential_flags", {})

        masked_seq_value = syscall_arg_value & ~(masked_bits)

        candidate = sequential_flags.get(masked_seq_value)
        if candidate is None:
            # If we don't find a base sequential let's not bother parsing ORed flags
            return default_val

        if out_mnemonic == "":
            out_mnemonic = candidate + f" ({syscall_arg_value:#x})"
        else:
            out_mnemonic += f" | {candidate} ({syscall_arg_value:#x})"
    elif parsing_mode == "custom":
        parser_func = specific_arg_map.get("parser")

        if parser_func is None:
            raise ValueError(
                f"Custom parser function not defined for syscall number {syscall_number}",
            )

        # Call the custom parser function
        out_mnemonic = parser_func(syscall_arg_value)

        if out_mnemonic is None or len(out_mnemonic) == 0:
            # If the custom parser returns None, use the default value
            out_mnemonic = default_val
        else:
            out_mnemonic += f" ({syscall_arg_value:#x})"
    else:
        raise ValueError(
            f"Unsupported parsing mode '{parsing_mode}' for syscall number {syscall_number}",
        )

    if len(out_mnemonic) == 0:
        return default_val

    # Before returning, escape the special characters
    return out_mnemonic
