#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from libdebug.data.section import Section
from libdebug.data.section_list import SectionList
from libdebug.utils.arch_mappings import map_arch
from libdebug.utils.elf_utils import elf_architecture, get_elf_sections, get_endianness, get_entry_point, is_pie

if TYPE_CHECKING:
    from libdebug.data.symbol_list import SymbolList
    from libdebug.debugger.internal_debugger import InternalDebugger


@dataclass
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
        symbols (SymbolList): The list of symbols in the ELF file.
    """

    path: str = ""
    """Path to the ELF file."""

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

    _base_address: int = 0x0
    """Base address where the ELF file is loaded in memory."""

    _symbols: SymbolList | None = None
    """List of symbols in the ELF file."""

    _internal_debugger: InternalDebugger | None = None
    """The instance of InternalDebugger"""

    @staticmethod
    def parse(path: str, base_address: int, internal_debugger: InternalDebugger) -> ELF:
        """Parses an ELF from a path.

        Args:
            path (str): The path to the ELF file.
            base_address (int): The base address where the ELF file is loaded in memory.
            internal_debugger (InternalDebugger): The instance of InternalDebugger.

        Returns:
            ELF: The parsed ELF file.
        """
        is_pie_ = is_pie(path)
        entry_point_ = get_entry_point(path)
        architecture_ = map_arch(elf_architecture(path))
        endianness_ = get_endianness(path)

        return ELF(
            path=path,
            entry_point=entry_point_,
            is_pie=is_pie_,
            architecture=architecture_,
            endianness=endianness_,
            _base_address=base_address,
            _internal_debugger=internal_debugger,
        )

    @property
    def sections(self: ELF) -> SectionList:
        """The list of sections in the ELF file."""
        if self._sections is None:
            table = get_elf_sections(self.path)

            parsed_sections = [
                Section(
                    name=section_info.name,
                    section_type_val=section_info.type,
                    flags=section_info.flags,
                    address=section_info.addr,
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

        id_section = None

        for section in self.sections:
            if section.name == ".note.gnu.build-id":
                id_section = section
                break

        if id_section is not None:
            with Path(self.path).open("rb") as f:
                f.seek(id_section.offset)
                data = f.read(id_section.size)
                if len(data) >= 16:
                    self._build_id = data[16:].hex()
                    return self._build_id

        return None

    @property
    def base_address(self: ELF) -> int:
        """The base address where the ELF file is loaded in memory."""
        if self._base_address == 0x0:
            raise ValueError("Base address not yet resolved. Did you run or attach to the process?")

        return self._base_address

    @property
    def symbols(self: ELF) -> SymbolList:
        """The list of symbols in the ELF file."""
        if self._symbols is None:
            if not self._internal_debugger.is_debugging:
                raise ValueError("You must run or attach to the process before accessing symbols.")

            full_path_elf = Path(self.path)

            self._symbols = [
                sym
                for sym in self._internal_debugger.symbols
                if full_path_elf.samefile(Path(sym.backing_file))
            ]
        return self._symbols

    def pprint_sections(self: ELF) -> None:
        """Pretty-prints the sections of the ELF file."""
        console = Console()
        table = Table(title=f"Sections in {self.path}")

        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Type", style="magenta")
        table.add_column("Flags", style="green")
        table.add_column("Address", style="yellow")
        table.add_column("Offset", style="blue")
        table.add_column("Size", style="red")
        table.add_column("Align", style="white")

        for section in self.sections:
            table.add_row(
                section.name,
                section.section_type.name,
                section.flags,
                f"{section.start:#x}",
                f"{section.offset:#x}",
                f"{section.size:#x}",
                f"{section.address_align}",
            )

        console.print(table)

    def __repr__(self: ELF) -> str:
        """Return the string representation of the binary."""
        base_address_repr = f"{self._base_address:#x}" if self._base_address != 0x0 else "Not yet resolved"
        return f"ELF(path={self.path}, base_address={base_address_repr}, entry_point={self.entry_point:#x}, is_pie={self.is_pie}, architecture={self.architecture}, endianness={self.endianness}, build_id={self.build_id})"
