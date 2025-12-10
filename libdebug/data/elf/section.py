#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class Section:
    """Represents a section in an ELF file."""

    def __init__(
        self: Section,
        name: str,
        section_type: str,
        flags: int,
        address: int,
        offset: int,
        size: int,
        address_align: int,
        reference_file: str,
    ) -> None:
        """Initializes the Section.

        Args:
            name (str): The name of the section.
            section_type (str): The mnemonic of the type of the section from the define (e.g., PROGBITS, SYMTAB).
            flags (str): The flags associated with the section (e.g., X, W, R).
            address (int): The virtual address of the section in memory.
            offset (int): The offset of the section in the file.
            size (int): The size of the section in bytes.
            address_align (int): The required alignment of the section.
            reference_file (str): The path to the ELF file containing this section.
        """
        self.name = name
        self.section_type = section_type
        self.flags = flags
        self.address = address
        self.offset = offset
        self.size = size
        self.address_align = address_align
        self.reference_file = reference_file

    def __repr__(self: Section) -> str:
        """Return a developer-oriented string representation of the Section."""
        return (
            f'Section(name="{self.name}", section_type={self.section_type}, flags={self.flags}, '
            f"address={self.address:#x}, offset={self.offset:#x}, size={self.size:#x}, "
            f'reference_file="{self.reference_file}")'
        )
