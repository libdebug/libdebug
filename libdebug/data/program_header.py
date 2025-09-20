#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProgramHeader:
    """Represents a program header in an ELF file."""

    header_type: str = ""
    """The type of the program header (e.g., LOAD, DYNAMIC, INTERP, etc.)."""

    offset: int = 0
    """The offset of the program header in the file."""

    vaddr: int = 0
    """The virtual address of the program header in memory."""

    paddr: int = 0
    """The physical address of the program header (if applicable)."""

    filesz: int = 0
    """The size of the segment in the file."""

    memsz: int = 0
    """The size of the segment in memory."""

    flags: str = ""
    """The flags associated with the program header (e.g., R, W, X)."""

    align: int = 0
    """The alignment of the segment in memory."""

    reference_file: str = ""
    """The path to the ELF file containing this program header."""

    def __repr__(self: ProgramHeader) -> str:
        """Returns a string representation of the ProgramHeader."""
        return (
            f"ProgramHeader(header_type={self.type}, offset={self.offset:#x}, vaddr={self.vaddr:#x}, "
            f"paddr={self.paddr:#x}, filesz={self.filesz:#x}, memsz={self.memsz:#x}, "
            f"flags='{self.flags}', align={self.align:#x}, reference_file='{self.reference_file}')"
        )
