#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio,  Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.memory_map_list import MemoryMapList
from libdebug.data.registers import Registers
from libdebug.data.symbol_list import SymbolList
from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.debugging_utils import resolve_address_in_maps


def pprint_maps_util(maps: MemoryMapList | MemoryMapSnapshotList) -> None:
    """Prints the memory maps of the process."""
    header = (
        f"{'start':>18}  " f"{'end':>18}  " f"{'perm':>6}  " f"{'size':>8}  " f"{'offset':>8}  " f"{'backing_file':<20}"
    )
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


def pprint_backtrace_util(backtrace: list, maps: MemoryMapList | MemoryMapSnapshotList, external_symbols: SymbolList = None) -> None:
    """Pretty prints the current backtrace of the thread."""
    for return_address in backtrace:
        filtered_maps = maps.filter(return_address)
        return_address_symbol = resolve_address_in_maps_util(return_address, filtered_maps, external_symbols)
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


def pprint_registers_util(registers: Registers, maps: MemoryMapList, gen_regs: list[str]) -> None:
    """Pretty prints the thread's registers."""
    for curr_reg in gen_regs:
        _pprint_reg(registers, maps, curr_reg)


def pprint_registers_all_util(
    registers: Registers, maps: MemoryMapList, gen_regs: list[str], spec_regs: list[str], vec_fp_regs: list[str],
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


def resolve_address_in_maps_util(
    address: int, maps: MemoryMapList | MemoryMapSnapshotList, external_symbols: SymbolList = None,
) -> str:
    """Resolves the address in the specified memory maps."""
    is_snapshot = isinstance(maps, MemoryMapSnapshotList)

    if not is_snapshot:
        return resolve_address_in_maps(address, maps)
    else:
        if external_symbols is None:
            raise ValueError("External symbols must be provided when resolving an address in a snapshot.")

        matching_symbols = external_symbols._search_by_address_in_snapshot(address, maps)

        if len(matching_symbols) == 0:
            return f"0x{address:x}"
        elif len(matching_symbols) > 1:
            liblog.warning(f"Multiple symbols found for address {address:#x}. Taking the first one.")

        return matching_symbols[0].name
