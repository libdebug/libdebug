#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from libdebug.data.elf.dynamic_section import DynamicSection
from libdebug.data.elf.dynamic_section_list import DynamicSectionList
from libdebug.data.elf.gnu_property import GNUProperty
from libdebug.data.elf.gnu_property_list import GNUPropertyList
from libdebug.data.elf.linux_runtime_mitigations import LinuxRuntimeMitigations
from libdebug.data.elf.program_header import ProgramHeader
from libdebug.data.elf.program_header_list import ProgramHeaderList
from libdebug.data.elf.section import Section
from libdebug.data.elf.section_list import SectionList
from libdebug.data.symbol_list import SymbolList
from libdebug.native.libdebug_elf_api import DynSectionValueType
from libdebug.utils.arch_mappings import map_arch
from libdebug.utils.elf_utils import (
    elf_architecture,
    get_elf_dynamic_sections,
    get_elf_gnu_property_notes,
    get_elf_program_headers,
    get_elf_sections,
    get_endianness,
    get_entry_point,
    is_pie,
)

if TYPE_CHECKING:
    from libdebug.data.symbol_list import SymbolList
    from libdebug.debugger.internal_debugger import InternalDebugger


@dataclass
class ELF:
    """An ELF file involved in the target process.

    Attributes:
        path (str): The path to the ELF file.
        absolute_path (str): The absolute path to the ELF file.
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

    absolute_path: str = ""
    """Absolute path to the ELF file."""

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

    _dynamic_sections: DynamicSectionList | None = None
    """List of dynamic sections in the ELF file."""

    _program_headers: ProgramHeaderList | None = None
    """List of program headers in the ELF file."""

    _gnu_properties: GNUPropertyList | None = None
    """List of GNU properties in the ELF file."""

    _build_id: str | None = None
    """Build ID of the ELF file, if available."""

    _base_address: int = 0x0
    """Base address where the ELF file is loaded in memory."""

    _symbols: SymbolList | None = None
    """List of symbols in the ELF file."""

    _runtime_mitigations: LinuxRuntimeMitigations | None = None
    """The Linux runtime mitigations of the ELF file."""

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
            absolute_path=str(Path(path).resolve()),
            entry_point=entry_point_,
            is_pie=is_pie_,
            architecture=architecture_,
            endianness=endianness_,
            _base_address=base_address,
            _internal_debugger=internal_debugger,
        )

    @property
    def arch(self: ELF) -> str:
        """Alias for architecture."""
        return self.architecture

    @functools.cached_property
    def size(self: ELF) -> int:
        """The size of the ELF file in bytes."""
        return Path(self.path).stat().st_size

    @property
    def sections(self: ELF) -> SectionList:
        """The list of sections in the ELF file."""
        if self._sections is None:
            table = get_elf_sections(self.path)

            parsed_sections = [
                Section(
                    name=section_info.name,
                    section_type=section_info.type,
                    flags=section_info.flags,
                    address=section_info.addr,
                    offset=section_info.offset,
                    size=section_info.size,
                    address_align=section_info.addralign,
                    reference_file=self.absolute_path,
                )
                for section_info in table.sections
            ]

            self._sections = SectionList(parsed_sections)
        return self._sections

    @property
    def dynamic_sections(self: ELF) -> DynamicSectionList:
        """The list of dynamic sections in the ELF file."""
        if self._dynamic_sections is None:
            table = get_elf_dynamic_sections(self.path)

            parsed_dynamic_sections = [
                DynamicSection(
                    tag=dyn_section.tag,
                    # Value can be either an int or a str depending on the type of the dynamic section
                    value=(
                        dyn_section.val
                        if dyn_section.val_type
                        in (
                            DynSectionValueType.NONE,
                            DynSectionValueType.NUM,
                            DynSectionValueType.ADDR,
                        )
                        else dyn_section.val_str
                    ),
                    is_value_address=dyn_section.val_type == DynSectionValueType.ADDR,
                    reference_file=self.absolute_path,
                )
                for dyn_section in table.entries
            ]

            self._dynamic_sections = DynamicSectionList(parsed_dynamic_sections)
        return self._dynamic_sections

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

            full_path_elf = Path(self.absolute_path)

            self._symbols = SymbolList(
                [sym for sym in self._internal_debugger.symbols if full_path_elf.samefile(Path(sym.backing_file))],
                maps_source=self._internal_debugger,
            )
        return self._symbols

    @property
    def soname(self: ELF) -> str | None:
        """The SONAME of the ELF file, if available.

        Returns:
            str | None: The SONAME of the shared object ELF file, or None if not a library.
        """
        soname_entries = self.dynamic_sections.filter("SONAME")
        if len(soname_entries) > 0:
            return soname_entries[0].value if isinstance(soname_entries[0].value, str) else None
        return None

    @property
    def program_headers(self: ELF) -> ProgramHeaderList:
        """The program headers of the ELF file."""
        if self._program_headers is None:
            table = get_elf_program_headers(self.path)

            parsed_program_headers = [
                ProgramHeader(
                    header_type=ph_info.type,
                    offset=ph_info.offset,
                    vaddr=ph_info.vaddr,
                    paddr=ph_info.paddr,
                    filesz=ph_info.filesz,
                    memsz=ph_info.memsz,
                    flags=ph_info.flags,
                    align=ph_info.align,
                    reference_file=self.absolute_path,
                )
                for ph_info in table.headers
            ]

            self._program_headers = ProgramHeaderList(parsed_program_headers)

        return self._program_headers

    @property
    def gnu_properties(self: ELF) -> GNUPropertyList:
        """The GNU properties of the ELF file."""
        if self._gnu_properties is None:
            table = get_elf_gnu_property_notes(self.path)

            parsed_gnu_properties = []

            for note in table.properties:
                pr_type = note.type

                # Determine the value based on the note content
                if note.is_bit_mask or note.bit_mnemonics:
                    value = note.bit_mnemonics
                elif len(note.data) in (4, 8):
                    value = int.from_bytes(note.data, byteorder=self.endianness)
                else:
                    value = note.data

                parsed_gnu_properties.append(
                    GNUProperty(
                        pr_type=pr_type,
                        value=value,
                        reference_file=self.absolute_path,
                    ),
                )

            self._gnu_properties = GNUPropertyList(parsed_gnu_properties)

        return self._gnu_properties

    @property
    def runtime_mitigations(self: ELF) -> LinuxRuntimeMitigations:
        """The Linux runtime mitigations of the ELF file."""
        if self._runtime_mitigations is None:
            self._runtime_mitigations = LinuxRuntimeMitigations.parse_elf(self, self._internal_debugger.is_debugging)
        return self._runtime_mitigations

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
                section.section_type,
                section.flags,
                f"{section.address:#x}",
                f"{section.offset:#x}",
                f"{section.size:#x}",
                f"{section.address_align}",
            )

        console.print(table)

    def pprint_dynamic_sections(self: ELF) -> None:
        """Pretty-prints the dynamic sections of the ELF file."""
        console = Console()
        table = Table(title=f"Dynamic Sections in {self.path}")

        table.add_column("Tag", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        for dyn_section in self.dynamic_sections:
            if dyn_section.is_value_address and isinstance(dyn_section.value, int):
                value_str = f"{dyn_section.value:#x}"
            elif isinstance(dyn_section.value, str):
                value_str = dyn_section.value
            elif isinstance(dyn_section.value, int):
                value_str = str(dyn_section.value)
            else:
                value_str = str(dyn_section.value)

            table.add_row(dyn_section.tag, value_str)

        console.print(table)

    def pprint_program_headers(self: ELF) -> None:
        """Pretty-prints the program headers of the ELF file."""
        console = Console()
        table = Table(title=f"Program Headers in {self.path}")

        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Offset", style="magenta")
        table.add_column("Vaddr", style="green")
        table.add_column("Paddr", style="yellow")
        table.add_column("Filesz", style="blue")
        table.add_column("Memsz", style="red")
        table.add_column("Flags", style="white")
        table.add_column("Align", style="white")

        for ph in self.program_headers:
            table.add_row(
                ph.header_type,
                f"{ph.offset:#x}",
                f"{ph.vaddr:#x}",
                f"{ph.paddr:#x}",
                f"{ph.filesz:#x}",
                f"{ph.memsz:#x}",
                ph.flags,
                f"{ph.align:#x}",
            )

        console.print(table)

    def pprint_gnu_properties(self: ELF) -> None:
        """Pretty-prints the GNU properties of the ELF file."""
        console = Console()
        table = Table(title=f"GNU Properties in {self.path}")

        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Data", style="magenta")

        for prop in self.gnu_properties:
            if isinstance(prop.value, int):
                data_str = f"{prop.value:#x}"
            elif isinstance(prop.value, bytes):
                data_str = prop.value.hex()
            elif isinstance(prop.value, list):
                data_str = ", ".join(prop.value)
            else:
                data_str = str(prop.value)

            table.add_row(prop.pr_type, data_str)

        console.print(table)

    def __repr__(self: ELF) -> str:
        """Return the string representation of the binary."""
        base_address_repr = f"{self._base_address:#x}" if self._base_address != 0x0 else "Not yet resolved"
        so_addition = f"soname={self.soname}, " if self.soname else ""

        return (
            f"ELF({so_addition}path={self.path}, base_address={base_address_repr}, "
            f"entry_point={self.entry_point:#x}, "
            f"is_pie={self.is_pie}, "
            f"architecture={self.architecture}, "
            f"endianness={self.endianness}, "
            f"build_id={self.build_id})"
        )
