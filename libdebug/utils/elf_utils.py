#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
from pathlib import Path

import requests
from elftools.elf.elffile import ELFFile

from libdebug.cffi.debug_sym_cffi import ffi
from libdebug.cffi.debug_sym_cffi import lib as lib_sym
from libdebug.liblog import liblog
from libdebug.utils.libcontext import libcontext

DEBUGINFOD_PATH: Path = Path.home() / ".cache" / "debuginfod_client"
LOCAL_DEBUG_PATH: Path = Path("/usr/lib/debug/.build-id/")
URL_BASE: str = "https://debuginfod.elfutils.org/buildid/{}/debuginfo"


def _download_debuginfod(buildid: str, debuginfod_path: Path) -> None:
    """Downloads the debuginfo file corresponding to the specified buildid.

    Args:
        buildid (str): The buildid of the debuginfo file.
        debuginfod_path (Path): The output directory.
    """
    try:
        url = URL_BASE.format(buildid)
        r = requests.get(url, allow_redirects=True, timeout=1)

        if r.ok:
            debuginfod_path.parent.mkdir(parents=True, exist_ok=True)

            with debuginfod_path.open("wb") as f:
                f.write(r.content)
    except Exception as e:
        liblog.debugger(f"Exception {e} occurred while downloading debuginfod symbols")


@functools.cache
def _debuginfod(buildid: str) -> Path:
    """Returns the path to the debuginfo file corresponding to the specified buildid.

    Args:
        buildid (str): The buildid of the debuginfo file.

    Returns:
        debuginfod_path (Path): The path to the debuginfo file corresponding to the specified buildid.
    """
    debuginfod_path = Path.home() / ".cache" / "debuginfod_client" / buildid / "debuginfo"

    if not debuginfod_path.exists():
        _download_debuginfod(buildid, debuginfod_path)

    return debuginfod_path


@functools.cache
def _collect_external_info(path: str) -> dict[str, tuple[int, int]]:
    """Returns a dictionary containing the symbols taken from the external debuginfo file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        symbols (dict): A dictionary containing the symbols of the specified external debuginfo file.
    """
    symbols = {}

    c_file_path = ffi.new("char[]", path.encode("utf-8"))
    head = lib_sym.collect_external_symbols(c_file_path, libcontext.sym_lvl)

    if head != ffi.NULL:
        cursor = head

        while cursor != ffi.NULL:
            symbol_name = ffi.string(cursor.name).decode("utf-8")
            symbols[symbol_name] = (cursor.low_pc, cursor.high_pc)
            cursor = cursor.next

        lib_sym.free_symbol_info(head)

    return symbols


@functools.cache
def _parse_elf_file(path: str, debug_info_level: int) -> tuple[dict[str, tuple[int, int]], str | None, str | None]:
    """Returns a dictionary containing the symbols of the specified ELF file and the buildid.

    Args:
        path (str): The path to the ELF file.
        debug_info_level (int): The debug info level.

    Returns:
        symbols (dict): A dictionary containing the symbols of the specified ELF file.
        buildid (str): The buildid of the specified ELF file.
        debug_file_path (str): The path to the external debuginfo file corresponding.
    """
    symbols = {}
    buildid = None
    debug_file_path = None

    c_file_path = ffi.new("char[]", path.encode("utf-8"))
    head = lib_sym.read_elf_info(c_file_path, debug_info_level)

    if head != ffi.NULL:
        cursor = head

        while cursor != ffi.NULL:
            symbol_name = ffi.string(cursor.name).decode("utf-8")
            symbols[symbol_name] = (cursor.low_pc, cursor.high_pc)
            cursor = cursor.next

        lib_sym.free_symbol_info(head)

    if debug_info_level > 2:
        buildid = lib_sym.get_build_id()
        buildid = ffi.string(buildid).decode("utf-8") if buildid != ffi.NULL else None

        debug_file_path = lib_sym.get_debug_file()
        debug_file_path = ffi.string(debug_file_path).decode("utf-8") if debug_file_path != ffi.NULL else None

    return symbols, buildid, debug_file_path


@functools.cache
def resolve_symbol(path: str, symbol: str) -> int:
    """Returns the address of the specified symbol in the specified ELF file.

    Args:
        path (str): The path to the ELF file.
        symbol (str): The symbol whose address should be returned.

    Returns:
        int: The address of the specified symbol in the specified ELF file.
    """
    if libcontext.sym_lvl == 0:
        raise Exception(
            "Symbol resolution is disabled. Please enable it by setting the sym_lvl libcontext parameter to a value greater than 0.",
        )

    # Retrieve the symbols from the SymbolTableSection
    symbols, buildid, debug_file = _parse_elf_file(path, libcontext.sym_lvl)
    if symbol in symbols:
        return symbols[symbol][0]

    # Retrieve the symbols from the external debuginfo file
    if buildid and debug_file and libcontext.sym_lvl > 2:
        folder = buildid[:2]
        absolute_debug_path_str = str((LOCAL_DEBUG_PATH / folder / debug_file).resolve())
        symbols = _collect_external_info(absolute_debug_path_str)
        if symbol in symbols:
            return symbols[symbol][0]

    # Retrieve the symbols from debuginfod
    if buildid and libcontext.sym_lvl > 4:
        absolute_debug_path = _debuginfod(buildid)
        if absolute_debug_path.exists():
            symbols = _collect_external_info(str(absolute_debug_path))
            if symbol in symbols:
                return symbols[symbol][0]

    # Symbol not found
    raise ValueError(f"Symbol {symbol} not found in {path}. Please specify a valid symbol.")


@functools.cache
def resolve_address(path: str, address: int) -> str:
    """Returns the symbol corresponding to the specified address in the specified ELF file.

    Args:
        path (str): The path to the ELF file.
        address (int): The address whose symbol should be returned.

    Returns:
        str: The symbol corresponding to the specified address in the specified ELF file.
    """
    if libcontext.sym_lvl == 0:
        return hex(address)

    # Retrieve the symbols from the SymbolTableSection
    symbols, buildid, debug_file = _parse_elf_file(path, libcontext.sym_lvl)
    for symbol, (symbol_start, symbol_end) in symbols.items():
        if symbol_start <= address < symbol_end:
            return f"{symbol}+{address-symbol_start:x}"

    # Retrieve the symbols from the external debuginfo file
    if buildid and debug_file and libcontext.sym_lvl > 2:
        folder = buildid[:2]
        absolute_debug_path_str = str((LOCAL_DEBUG_PATH / folder / debug_file).resolve())
        symbols = _collect_external_info(absolute_debug_path_str)
        for symbol, (symbol_start, symbol_end) in symbols.items():
            if symbol_start <= address < symbol_end:
                return f"{symbol}+{address-symbol_start:x}"

    # Retrieve the symbols from debuginfod
    if buildid and libcontext.sym_lvl > 4:
        absolute_debug_path = _debuginfod(buildid)
        if absolute_debug_path.exists():
            symbols = _collect_external_info(str(absolute_debug_path))
            for symbol, (symbol_start, symbol_end) in symbols.items():
                if symbol_start <= address < symbol_end:
                    return f"{symbol}+{address-symbol_start:x}"

    # Address not found
    raise ValueError(f"Address {hex(address)} not found in {path}. Please specify a valid address.")


@functools.cache
def is_pie(path: str) -> bool:
    """Returns True if the specified ELF file is position independent, False otherwise.

    Args:
        path (str): The path to the ELF file.

    Returns:
        bool: True if the specified ELF file is position independent, False otherwise.
    """
    with Path(path).open("rb") as elf_file:
        elf = ELFFile(elf_file)

    return elf.header.e_type == "ET_DYN"


@functools.cache
def get_entry_point(path: str) -> int:
    """Returns the entry point of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        int: The entry point of the specified ELF file.
    """
    with Path(path).open("rb") as elf_file:
        elf = ELFFile(elf_file)

    return elf.header.e_entry
