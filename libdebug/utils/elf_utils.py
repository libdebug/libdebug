#
# This file is part of libdebug Python library (https://github.com/gabriele180698/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

from elftools.elf.elffile import ELFFile
import functools


@functools.cache
def parse_elf_symbols(path: str) -> dict[str, int]:
    """Returns a dictionary containing the symbols of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        dict: A dictionary containing the symbols of the specified ELF file.
    """
    symbols = {}

    with open(path, "rb") as elf_file:
        elf = ELFFile(elf_file)
        for section in elf.iter_sections():
            if section.name == ".symtab":
                for symbol in section.iter_symbols():
                    symbols[symbol.name] = symbol.entry.st_value

    return symbols


def get_symbol_address(path: str, symbol: str) -> int:
    """Returns the address of the specified symbol in the specified ELF file.

    Args:
        path (str): The path to the ELF file.
        symbol (str): The symbol whose address should be returned.

    Returns:
        int: The address of the specified symbol in the specified ELF file.
    """
    symbols = parse_elf_symbols(path)
    if symbol not in symbols:
        raise ValueError(f"Symbol {symbol} not found in {path}. Please specify a valid symbol.")
    return symbols[symbol]
