#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


def or_parse(arg_map: dict, value: int) -> str:
    """Parse the syscall argument value using OR logic.

    Args:
        arg_map (dict): The argument map containing mnemonics and masks.
        value (int): The syscall argument value.

    Returns:
        str: The parsed syscall argument value.
    """
    # At this point than one mnemonic is likely
    out_mnemonic = ""

    masked_bits = 0x000000000000000000

    for mnemonic_mask, mnemonic in arg_map.items():
        if not isinstance(mnemonic_mask, int):
            # If the mask is not an integer, skip it
            # it's string metadata
            continue

        if mnemonic_mask == 0 and value != 0:
            # If the mask is 0 and the syscall argument value is not 0, skip it
            continue

        # Check if the syscall argument value matches the mnemonic mask
        if mnemonic_mask & value == mnemonic_mask:
            if len(out_mnemonic) == 0:
                out_mnemonic = mnemonic
            else:
                out_mnemonic += f" | {mnemonic}"

            masked_bits |= mnemonic_mask

    # If not all bits are masked, add the remaining bits to the mnemonic in OR
    if ~masked_bits & value != 0 and len(out_mnemonic) > 0:
        out_mnemonic += " | " + f"{value & ~masked_bits:#08x}"

    if out_mnemonic != "":
        out_mnemonic += f" ({value:#x})"

    return out_mnemonic


def sequential_parse(arg_map: dict, value: int) -> str:
    """Parse the syscall argument value using sequential logic.

    Args:
        arg_map (dict): The argument map containing mnemonics and masks.
        value (int): The syscall argument value.

    Returns:
        str: The parsed syscall argument value.
    """
    out_mnemonic = arg_map.get(value, None)

    if out_mnemonic != None:
        out_mnemonic += f" ({value:#x})"
    else:
        # If the value is not found in the map, return the default value
        out_mnemonic = f"{value:#x}"

    return out_mnemonic
