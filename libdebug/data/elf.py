#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.data.section import Section
from libdebug.data.section_list import SectionList
from libdebug.utils.elf_utils import elf_architecture, get_elf_sections, get_endianness, get_entry_point, is_pie


@dataclass(frozen=True)
class ELF:
    """An ELF file involved in the target process.

    Attributes:
        path (str): The path to the ELF file.
        base_address (int): The base address where the ELF file is loaded in memory.
        entry_point (int): The entry point of the ELF file.
        is_pie (bool): Whether the ELF file is position-independent (PIE) or not.
        architecture (str): The architecture of the ELF file (e.g., x86, x86_64, arm, aarch64).
        endianness (str): The endianness of the ELF file (e.g., little, big).
        sections (SectionList): The list of sections in the ELF file.
        build_id (str): The build ID of the ELF file, if available.
    """

    path: str = ""
    """Path to the ELF file."""

    base_address: int = 0
    """Base address where the ELF file is loaded in memory."""

    entry_point: int = 0
    """Entry point of the ELF file."""

    is_pie: bool = False
    """Whether the ELF file is position-independent (PIE) or not."""

    architecture: str = ""
    """Architecture of the ELF file (e.g., x86, x86_64, arm, aarch64)."""

    endianness: str = ""
    """Endianness of the ELF file (e.g., little, big)."""

    _sections: SectionList | None = None
    """List of sections in the ELF file."""

    _build_id: str | None = None
    """Build ID of the ELF file, if available."""

    @staticmethod
    def parse_base(path: str, base: int) -> ELF:
        """Parses an ELF from a path.

        Args:
            path (str): The path to the ELF file.
            base (int): The base address where the ELF file is loaded in memory.

        Returns:
            ELF: The parsed ELF file.
        """
        is_pie_ = is_pie(path)
        entry_point_ = get_entry_point(path)
        architecture_ = elf_architecture(path)
        endianness_ = get_endianness(path)
        return ELF(
            path=path,
            base_address=base,
            entry_point=entry_point_,
            is_pie=is_pie_,
            architecture=architecture_,
            endianness=endianness_,
        )

    @property
    def sections(self: ELF) -> SectionList:
        """The list of sections in the ELF file."""
        if self._sections is None:
            table = get_elf_sections(self.path)

            parsed_sections = [
                Section(
                    name=section_info.name,
                    type=section_info.type,
                    flags=section_info.flags,
                    address=section_info.address,
                    offset=section_info.offset,
                    size=section_info.size,
                    address_align=section_info.addralign,
                    reference_file=self.path,
                )
                for section_info in table.sections
            ]

            self._sections = SectionList(parsed_sections)
        return self._sections

    @property
    def build_id(self: ELF) -> str | None:
        """The build ID of the ELF file, if available."""
        if self._build_id is not None:
            return self._build_id

        for section in self.sections:
            if section.name == ".note.gnu.build-id":
                self._build_id = section.get_build_id()
                return self._build_id

        return None

    def __repr__(self: ELF) -> str:
        """Return the string representation of the binary."""
        return f"ELF(path={self.path}, base_address={self.base_address:#x}, entry_point={self.entry_point:#x}, is_pie={self.is_pie}, architecture={self.architecture}, endianness={self.endianness}, build_id={self.build_id}, is_shared_object={self.is_shared_object})"
