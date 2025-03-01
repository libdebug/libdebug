#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.memory_map_list import MemoryMapList
from libdebug.data.registers import Registers
from libdebug.data.symbol_list import SymbolList
from libdebug.debugger.internal_debugger_instance_manager import extend_internal_debugger
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.debugging_utils import resolve_symbol_name_in_maps_util


def pprint_maps_util(maps: MemoryMapList | MemoryMapSnapshotList) -> None:
    """Prints the memory maps of the process."""
    header = f"{'start':>18}  {'end':>18}  {'perm':>6}  {'size':>8}  {'offset':>8}  {'backing_file':<20}"
    print(header)
    for memory_map in maps:
        info = (
            f"{memory_map.start:#18x}  "
            f"{memory_map.end:#18x}  "
            f"{memory_map.permissions:>6}  "
            f"{memory_map.size:#8x}  "
            f"{memory_map.offset:#8x}  "
            f"{memory_map.backing_file}"
        )
        if "rwx" in memory_map.permissions:
            print(f"{ANSIColors.RED}{ANSIColors.UNDERLINE}{info}{ANSIColors.RESET}")
        elif "x" in memory_map.permissions:
            print(f"{ANSIColors.RED}{info}{ANSIColors.RESET}")
        elif "w" in memory_map.permissions:
            print(f"{ANSIColors.YELLOW}{info}{ANSIColors.RESET}")
        elif "r" in memory_map.permissions:
            print(f"{ANSIColors.GREEN}{info}{ANSIColors.RESET}")
        else:
            print(info)


def pprint_backtrace_util(
    backtrace: list, maps: MemoryMapList | MemoryMapSnapshotList, external_symbols: SymbolList = None
) -> None:
    """Pretty prints the current backtrace of the thread."""
    for return_address in backtrace:
        filtered_maps = maps.filter(return_address)
        with extend_internal_debugger(maps._internal_debugger):
            return_address_symbol = resolve_symbol_name_in_maps_util(return_address, filtered_maps, external_symbols)
        permissions = filtered_maps[0].permissions
        if "rwx" in permissions:
            style = f"{ANSIColors.UNDERLINE}{ANSIColors.RED}"
        elif "x" in permissions:
            style = f"{ANSIColors.RED}"
        elif "w" in permissions:
            # This should not happen, but it's here for completeness
            style = f"{ANSIColors.YELLOW}"
        elif "r" in permissions:
            # This should not happen, but it's here for completeness
            style = f"{ANSIColors.GREEN}"
        if return_address_symbol[:2] == "0x":
            print(f"{style}{return_address:#x} {ANSIColors.RESET}")
        else:
            print(f"{style}{return_address:#x} <{return_address_symbol}> {ANSIColors.RESET}")


def _pprint_reg(registers: Registers, maps: MemoryMapList, register: str) -> None:
    attr = getattr(registers, register)
    color = ""
    style = ""
    formatted_attr = f"{attr:#x}"

    if maps := maps.filter(attr):
        permissions = maps[0].permissions
        if "rwx" in permissions:
            color = ANSIColors.RED
            style = ANSIColors.UNDERLINE
        elif "x" in permissions:
            color = ANSIColors.RED
        elif "w" in permissions:
            color = ANSIColors.YELLOW
        elif "r" in permissions:
            color = ANSIColors.GREEN

    if color or style:
        formatted_attr = f"{color}{style}{attr:#x}{ANSIColors.RESET}"
    print(f"{ANSIColors.RED}{register}{ANSIColors.RESET}\t{formatted_attr}")


def _get_colored_address_string(address: int, maps: MemoryMapList):
    address_fixed = f"{address:#x}".rjust(18)

    if maps := maps.filter(address):
        permissions = maps[0].permissions
        if "rwx" in permissions:
            color = ANSIColors.RED
            style = ANSIColors.UNDERLINE
        elif "x" in permissions:
            color = ANSIColors.RED
            style = ""
        elif "w" in permissions:
            color = ANSIColors.YELLOW
            style = ""
        elif "r" in permissions:
            color = ANSIColors.GREEN
            style = ""
        return f"{color}{style}{address_fixed}{ANSIColors.RESET}"
    else:
        return f"{address_fixed}{ANSIColors.RESET}"


def pprint_registers_util(registers: Registers, maps: MemoryMapList, gen_regs: list[str]) -> None:
    """Pretty prints the thread's registers."""
    for curr_reg in gen_regs:
        _pprint_reg(registers, maps, curr_reg)


def pprint_registers_all_util(
    registers: Registers,
    maps: MemoryMapList,
    gen_regs: list[str],
    spec_regs: list[str],
    vec_fp_regs: list[str],
) -> None:
    """Pretty prints all the thread's registers."""
    pprint_registers_util(registers, maps, gen_regs)

    for t in spec_regs:
        _pprint_reg(registers, maps, t)

    for t in vec_fp_regs:
        print(f"{ANSIColors.BLUE}" + "{" + f"{ANSIColors.RESET}")
        for register in t:
            value = getattr(registers, register)
            formatted_value = f"{value:#x}" if isinstance(value, int) else str(value)
            print(f"  {ANSIColors.RED}{register}{ANSIColors.RESET}\t{formatted_value}")

        print(f"{ANSIColors.BLUE}" + "}" + f"{ANSIColors.RESET}")


def pprint_reg_diff_util(
    curr_reg: str,
    maps_before: MemoryMapList,
    maps_after: MemoryMapList,
    before: int,
    after: int,
) -> None:
    """Pretty prints a register diff."""
    before_str = _get_colored_address_string(before, maps_before)
    after_str = _get_colored_address_string(after, maps_after)

    print(f"{ANSIColors.RED}{curr_reg.ljust(12)}{ANSIColors.RESET}\t{before_str}\t{after_str}")


def pprint_reg_diff_large_util(
    curr_reg_tuple: (str, str),
    reg_tuple_before: (int, int),
    reg_tuple_after: (int, int),
) -> None:
    """Pretty prints a register diff."""
    print(f"{ANSIColors.BLUE}" + "{" + f"{ANSIColors.RESET}")
    for reg_name, value_before, value_after in zip(curr_reg_tuple, reg_tuple_before, reg_tuple_after, strict=False):
        has_changed = value_before != value_after

        # Print the old and new values
        if has_changed:
            formatted_value_before = (
                f"{ANSIColors.RED}{ANSIColors.STRIKE}"
                + (f"{value_before:#x}" if isinstance(value_before, int) else str(value_before))
                + f"{ANSIColors.RESET}"
            )

            formatted_value_after = (
                f"{ANSIColors.GREEN}"
                + (f"{value_after:#x}" if isinstance(value_after, int) else str(value_after))
                + f"{ANSIColors.RESET}"
            )

            print(
                f"  {ANSIColors.RED}{reg_name}{ANSIColors.RESET}\t{formatted_value_before}\t->\t{formatted_value_after}"
            )
        else:
            formatted_value = f"{value_before:#x}" if isinstance(value_before, int) else str(value_before)

            print(f"  {ANSIColors.RED}{reg_name}{ANSIColors.RESET}\t{formatted_value}")

    print(f"{ANSIColors.BLUE}" + "}" + f"{ANSIColors.RESET}")


def pprint_diff_line(content: str, is_added: bool) -> None:
    """Prints a line of a diff."""
    color = ANSIColors.GREEN if is_added else ANSIColors.RED

    prefix = ">>>" if is_added else "<<<"

    print(f"{prefix} {color}{content}{ANSIColors.RESET}")


def pprint_diff_substring(content: str, start: int, end: int) -> None:
    """Prints a diff with only a substring highlighted."""
    color = ANSIColors.ORANGE

    print(f"{content[:start]}{color}{content[start:end]}{ANSIColors.RESET}{content[end:]}")


def pprint_memory_util(
    address_start: int,
    extract: bytes,
    word_size: int,
    maps: MemoryMapList,
    integer_mode: bool = False,
) -> None:
    """Pretty prints the memory."""
    # Loop through each word-sized chunk
    for i in range(0, len(extract), word_size):
        # Calculate the current address
        current_address = address_start + i

        # Extract word-sized chunks from both extracts
        word = extract[i : i + word_size]

        # Convert each byte in the chunks to hex and compare
        formatted_word = [f"{byte:02x}" for byte in word]

        # Join the formatted bytes into a string for each column
        out = " ".join(formatted_word) if not integer_mode else "0x" + "".join(formatted_word[::-1])

        current_address_str = _get_colored_address_string(current_address, maps)

        # Print the memory diff with the address for this word
        print(f"{current_address_str}:  {out}")


def pprint_memory_diff_util(
    address_start: int,
    extract_before: bytes,
    extract_after: bytes,
    word_size: int,
    maps: MemoryMapSnapshotList,
    integer_mode: bool = False,
) -> None:
    """Pretty prints the memory diff."""
    # Loop through each word-sized chunk
    for i in range(0, len(extract_before), word_size):
        # Calculate the current address
        current_address = address_start + i

        # Extract word-sized chunks from both extracts
        word_before = extract_before[i : i + word_size]
        word_after = extract_after[i : i + word_size]

        # Convert each byte in the chunks to hex and compare
        formatted_before = []
        formatted_after = []
        for byte_before, byte_after in zip(word_before, word_after, strict=False):
            # Check for changes and apply color
            if byte_before != byte_after:
                formatted_before.append(f"{ANSIColors.RED}{byte_before:02x}{ANSIColors.RESET}")
                formatted_after.append(f"{ANSIColors.GREEN}{byte_after:02x}{ANSIColors.RESET}")
            else:
                formatted_before.append(f"{ANSIColors.RESET}{byte_before:02x}{ANSIColors.RESET}")
                formatted_after.append(f"{ANSIColors.RESET}{byte_after:02x}{ANSIColors.RESET}")

        # Join the formatted bytes into a string for each column
        if not integer_mode:
            before_str = " ".join(formatted_before)
            after_str = " ".join(formatted_after)
        else:
            # Right now libdebug only considers little-endian systems, if this changes,
            # this code should be passed the endianness of the system and format the bytes accordingly
            before_str = "0x" + "".join(formatted_before[::-1])
            after_str = "0x" + "".join(formatted_after[::-1])

        current_address_str = _get_colored_address_string(current_address, maps)

        # Print the memory diff with the address for this word
        print(f"{current_address_str}:  {before_str}    {after_str}")


def pprint_inline_diff(content: str, start: int, end: int, correction: str) -> None:
    """Prints a diff with inline changes."""
    print(
        f"{content[:start]}{ANSIColors.RED}{ANSIColors.STRIKE}{content[start:end]}{ANSIColors.RESET}{ANSIColors.GREEN}{correction}{ANSIColors.RESET}{content[start:]}"
    )
