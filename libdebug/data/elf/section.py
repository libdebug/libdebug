#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Section:
    """Represents a section in an ELF file."""

    name: str
    """The name of the section."""

    section_type: str
    """The mnemonic of the type of the section from the define (e.g., PROGBITS, SYMTAB)."""

    flags: int
    """The flags associated with the section (e.g., X, W, R)."""

    address: int
    """The virtual address of the section in memory."""

    offset: int
    """The offset of the section in the file."""

    size: int
    """The size of the section in bytes."""

    address_align: int
    """The required alignment of the section."""

    reference_file: str
    """The path to the ELF file containing this section."""

    def __repr__(self: Section) -> str:
        """Return a developer-oriented string representation of the Section."""
        return (
            f'Section(name="{self.name}", section_type={self.section_type}, flags={self.flags}, '
            f"address={self.address:#x}, offset={self.offset:#x}, size={self.size:#x}, "
            f'reference_file="{self.reference_file}")'
        )
