#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini, Gabriele Digregorio.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from elftools.elf.elffile import ELFFile, SymbolTableSection, NoteSection
import functools
import requests
from pathlib import Path
import os
from typing import IO

DEBUGINFOD_PATH: Path = Path.home() / ".cache" / "debuginfod_client"
LOCAL_DEBUG_PATH: bytes = b'/usr/lib/debug/.build-id/'

def _stream_loader(relative_file_path: str) -> IO[bytes]:
    """
    This function takes a relative file path to load a supplementary object file,
    and returns a stream suitable for creating a new ELFFile.

    Args:
        relative_file_path (str): The relative path to the supplementary object file.
    
    Returns:
        stream (IO[bytes]): A stream suitable for creating a new ELFFile.
    """
    global absolute_debug_path
    stream = open(absolute_debug_path + relative_file_path, 'rb')

    return stream


def _download_debuginfod(buildid: str, debuginfod_path: Path):
    """Downloads the debuginfo file corresponding to the specified buildid.

    Args:
        buildid (str): The buildid of the debuginfo file.
        debuginfod_path (Path): The output directory.
    """

    debuginfod_path.parent.mkdir(parents=True, exist_ok=True)

    url = f"https://debuginfod.elfutils.org/buildid/{buildid}/debuginfo"
    r = requests.get(url, allow_redirects=True)

    with open(debuginfod_path, "wb") as f:
        f.write(r.content)


def _debuginfod(buildid: str) -> str:
    """Returns the path to the debuginfo file corresponding to the specified buildid.

    Args:
        buildid (str): The buildid of the debuginfo file.

    Returns:
        str: The path to the debuginfo file corresponding to the specified buildid.
    """

    debuginfod_path = Path.home() / ".cache" / "debuginfod_client" / buildid / "debuginfo"

    if not debuginfod_path.exists():
        _download_debuginfod(buildid, debuginfod_path)

    return str(debuginfod_path)





def _symbols_from_debuglink(elf: ELFFile, buildid: str) -> dict[str, (int, int)]:
    """Returns a dictionary containing the symbols of the specified ELF file from the linked
    debug file.

    Args:
        elf (ELFFile): The ELF file.
        buildid (str): The buildid of the debuginfo file.
    
    Returns:
        dict: A dictionary containing the symbols of the specified ELF file.
    """
    global absolute_debug_path
    symbols = {}

    if not elf.has_dwarf_info():
        return symbols

    # Determine the path of the debuginfo file
    absolute_debug_path = LOCAL_DEBUG_PATH + buildid[:2].encode() + b'/'

    # Retrieve the symbols from the DWARF info
    dwarf_info = elf.get_dwarf_info(follow_links=True, relocate_dwarf_sections=True)

    if dwarf_info.supplementary_dwarfinfo:
        for CU in dwarf_info.supplementary_dwarfinfo.iter_CUs():
            print(CU.header)
            for DIE in CU.iter_DIEs():
                pass
                #if DIE.tag == 'DW_TAG_subprogram':
                    # Retrieve all attributes at once
                    #pass
                    #attributes = DIE.attributes
                    #lowpc_attr = attributes.get('DW_AT_low_pc')
                    #highpc_attr = attributes.get('DW_AT_high_pc')
                    #name_attr = attributes.get('DW_AT_name')

                    # Check if all necessary attributes are present
                    #if not lowpc_attr or not highpc_attr or not name_attr:
                    #    continue
                    
                    #lowpc = lowpc_attr.value
                    #if highpc_attr.form == 'DW_FORM_addr':
                    #    # highpc is an absolute address
                    #    size = highpc_attr.value - lowpc
                    #elif highpc_attr.form in {'DW_FORM_data2','DW_FORM_data4', 
                    #                            'DW_FORM_data8', 'DW_FORM_data1', 
                    #                            'DW_FORM_udata'}:
                    #    # highpc is an offset from lowpc
                    #    size = highpc_attr.value
                    
                    #name = name_attr.value
                    #symbols[name] = (lowpc, size)

       
    return symbols


def _iterate_sym_table(elf: ELFFile) -> dict[str, (int, int)]:
    """Returns a dictionary containing the symbols of the specified ELF file from 
    SymbolTableSection.

    Args:
        elf (ELFFile): The ELF file.

    Returns:
        dict: A dictionary containing the symbols of the specified ELF file.
    """
    symbols = {}

    # Retrieve the symbols from the SymbolTableSection
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                start_value = symbol.entry.st_value
                size_value = symbol.entry.st_size
                if start_value and size_value:
                    symbols[symbol.name] = (symbol.entry.st_value, symbol.entry.st_size)

    return symbols


def _retrieve_buildid(elf: ELFFile) -> str:
    """Returns the buildid of the specified ELF file.

    Args:
        elf (ELFFile): The ELF file.
    
    Returns:
        str: The buildid of the specified ELF file.
    """

    for section in elf.iter_sections():
        if section.name == '.note.gnu.build-id':
            for note in section.iter_notes():
                if note["n_type"] == "NT_GNU_BUILD_ID":
                    buildid = note["n_desc"]
    return buildid


@functools.cache
def _parse_elf_file(path: str, debug_info_level: int=2) -> dict[str, int]:
    """Returns a dictionary containing the symbols of the specified ELF file and
    the buildid.

    Args:
        path (str): The path to the ELF file.
        debug_info_level (int): The debug info level.

    Returns:
        symbols (dict): A dictionary containing the symbols of the specified ELF file.
        buildid (str): The buildid of the specified ELF file.
    """
    
    symbols_table = {}
    symbols_debug = {}


    with open(path, "rb") as elf_file:
        elf = ELFFile(elf_file, stream_loader=_stream_loader)

        # Retrieve the symbols from the SymbolTableSection
        symbols_table = _iterate_sym_table(elf)

        if debug_info_level >= 2:
            # Retrieve the buildid
            buildid = _retrieve_buildid(elf)



            # Retrieve the symbols from the DWARF info
            symbols_debug = _symbols_from_debuglink(elf, buildid)
        

    return symbols_table, buildid


def resolve_symbol(path: str, symbol: str) -> int:
    """Returns the address of the specified symbol in the specified ELF file.

    Args:
        path (str): The path to the ELF file.
        symbol (str): The symbol whose address should be returned.

    Returns:
        int: The address of the specified symbol in the specified ELF file.
    """

    global absolute_debug_path

    # Retrieve the symbols from the SymbolTableSection
    symbols, buildid = _parse_elf_file(path)

    if symbol in symbols:
        match = symbols[symbol][0]
    else:
        # Retrieve the symbols from the local debuginfo file

        if buildid:
            # Determine the path of the debuginfo file
            folder = buildid[:2].encode()
            absolute_debug_path = LOCAL_DEBUG_PATH + folder + b'/'
        else:
            # TODO log
            pass

        
    
    
    
    
    if symbol not in symbols:
        raise ValueError(
            f"Symbol {symbol} not found in {path}. Please specify a valid symbol."
        )
    
    return match

def resolve_address(path: str, address: int) -> str:
    """Returns the symbol corresponding to the specified address in the specified ELF file.

    Args:
        path (str): The path to the ELF file.
        address (int): The address whose symbol should be returned.

    Returns:
        str: The symbol corresponding to the specified address in the specified ELF file.
    """
    print(path)
    symbols, buildid = _parse_elf_file(path)
    for symbol, (symbol_address, symbol_size) in symbols.items():
        if symbol_address <= address < symbol_address + symbol_size:
            return f'{symbol}+{str(address-symbol_address)}'
    raise ValueError(
        f"Address {hex(address)} not found in {path}. Please specify a valid address."
    )


@functools.cache
def is_pie(path: str) -> bool:
    """Returns True if the specified ELF file is position independent, False otherwise.

    Args:
        path (str): The path to the ELF file.

    Returns:
        bool: True if the specified ELF file is position independent, False otherwise.
    """
    with open(path, "rb") as elf_file:
        elf = ELFFile(elf_file)

    return elf.header.e_type == "ET_DYN"
