#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import functools
import shutil
from pathlib import Path

from elftools.elf.elffile import ELFFile

from libdebug.native.libdebug_elf_api import (
    DynamicSectionTable,
    GNUPropertyNotesTable,
    ProgramHeaderTable,
    SectionTable,
)


@functools.cache
def parse_elf_characteristics(path: str) -> tuple[bool, int, str, str]:
    """Returns a tuple containing the PIE flag, the entry point, architecture and endianness of the ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        tuple: A tuple containing (is_pie, entry_point, architecture, endianness).
    """
    with Path(path).open("rb") as elf_file:
        elf = ELFFile(elf_file)

    pie = elf.header.e_type == "ET_DYN"
    entry_point = elf.header.e_entry
    arch = elf.get_machine_arch()
    endianness = "little" if elf.little_endian else "big"

    return pie, entry_point, arch, endianness


def is_pie(path: str) -> bool:
    """Returns True if the specified ELF file is position independent, False otherwise.

    Args:
        path (str): The path to the ELF file.

    Returns:
        bool: True if the specified ELF file is position independent, False otherwise.
    """
    return parse_elf_characteristics(path)[0]


def get_entry_point(path: str) -> int:
    """Returns the entry point of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        int: The entry point of the specified ELF file.
    """
    return parse_elf_characteristics(path)[1]


def elf_architecture(path: str) -> str:
    """Returns the architecture of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        str: The architecture of the specified ELF file.
    """
    return parse_elf_characteristics(path)[2]


def get_endianness(path: str) -> str:
    """Returns the endianness of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        str: The endianness of the specified ELF file.
    """
    return parse_elf_characteristics(path)[3]


def resolve_argv_path(argv_path: str) -> str:
    """Resolve the path of the binary to debug.

    Args:
        argv_path (str): The provided path of the binary to debug.

    Returns:
        str: The resolved path of the binary to debug.
    """
    argv_path_expanded = Path(argv_path).expanduser()

    # Check if the path is absolute after expansion
    if argv_path_expanded.is_absolute():
        # It's an absolute path, return it as is
        resolved_path = argv_path_expanded
    elif "/" in argv_path:
        # It already points to a file, resolve it and return as absolute
        resolved_path = argv_path_expanded.resolve().absolute()
    else:
        # Try to resolve the path using shutil
        resolved_path = abs_path if (abs_path := shutil.which(argv_path_expanded)) else argv_path_expanded
    return str(resolved_path)


@functools.cache
def is_elf(path: str) -> bool:
    """Check if the file at the given path is an ELF file.

    Args:
        path (str): The path to the file.

    Returns:
        bool: True if the file is an ELF file, False otherwise.
    """
    try:
        with Path(path).open("rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except OSError:
        return False


@functools.cache
def get_elf_sections(path: str) -> SectionTable:
    """Returns the sections of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        SectionTable: The sections of the specified ELF file.
    """
    return SectionTable.from_file(path)


@functools.cache
def get_elf_dynamic_sections(path: str) -> DynamicSectionTable:
    """Returns the dynamic sections of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        DynamicSectionTable: The dynamic sections of the specified ELF file.
    """
    return DynamicSectionTable.from_file(path)


@functools.cache
def get_elf_program_headers(path: str) -> ProgramHeaderTable:
    """Returns the program headers of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        ProgramHeaderTable: The program headers of the specified ELF file.
    """
    return ProgramHeaderTable.from_file(path)


@functools.cache
def get_elf_gnu_property_notes(path: str) -> GNUPropertyNotesTable:
    """Returns the GNU property notes of the specified ELF file.

    Args:
        path (str): The path to the ELF file.

    Returns:
        GNUPropertyNotesTable: The GNU property notes of the specified ELF file.
    """
    section_table = get_elf_sections(path)
    segment_table = get_elf_program_headers(path)

    note_gnu_prop_section = None

    for section in section_table.sections:
        if section.name == ".note.gnu.property":
            note_gnu_prop_section = section
            break

    note_gnu_prop_segment = None
    for segment in segment_table.headers:
        if segment.type == "GNU_PROPERTY":
            note_gnu_prop_segment = segment
            break

    section_start = int(note_gnu_prop_section.offset) if note_gnu_prop_section else 0
    section_size = int(note_gnu_prop_section.size) if note_gnu_prop_section else 0
    segment_start = int(note_gnu_prop_segment.offset) if note_gnu_prop_segment else 0
    segment_size = int(note_gnu_prop_segment.filesz) if note_gnu_prop_segment else 0

    return GNUPropertyNotesTable.from_file(path, section_start, section_size, segment_start, segment_size)
