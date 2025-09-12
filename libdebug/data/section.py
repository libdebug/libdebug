from __future__ import annotations

from enum import IntEnum


class SectionType(IntEnum):
    """Enumeration of ELF section types."""

    # System V + Update (Table 3-1)
    SHT_NULL = 0x0
    SHT_PROGBITS = 0x1
    SHT_SYMTAB = 0x2
    SHT_STRTAB = 0x3
    SHT_RELA = 0x4
    SHT_HASH = 0x5
    SHT_DYNAMIC = 0x6
    SHT_NOTE = 0x7
    SHT_NOBITS = 0x8
    SHT_REL = 0x9
    SHT_SHLIB = 0xA
    SHT_DYNSYM = 0xB
    SHT_INIT_ARRAY = 0xE
    SHT_FINI_ARRAY = 0xF
    SHT_PREINIT_ARRAY = 0x10

    # Processor / application specific bounds
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x7FFFFFFF
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xFFFFFFFF

    # Additional (Table 3-2)
    SHT_GNU_VERDEF = 0x6FFFFFFD
    SHT_GNU_VERNEED = 0x6FFFFFFE
    SHT_GNU_VERSYM = 0x6FFFFFFF

    @classmethod
    def _description_map(cls) -> dict[SectionType, str]:
        return {
            cls.SHT_NULL: "Inactive section header.",
            cls.SHT_PROGBITS: "Program-defined data.",
            cls.SHT_SYMTAB: "Full symbol table (mutually exclusive with SHT_DYNSYM).",
            cls.SHT_STRTAB: "String table.",
            cls.SHT_RELA: "Relocation entries with addends.",
            cls.SHT_HASH: "Symbol hash table.",
            cls.SHT_DYNAMIC: "Dynamic linking information.",
            cls.SHT_NOTE: "Auxiliary information (notes).",
            cls.SHT_NOBITS: "No file space; otherwise like PROGBITS (e.g. .bss).",
            cls.SHT_REL: "Relocation entries without addends.",
            cls.SHT_SHLIB: "Reserved (unspecified semantics).",
            cls.SHT_DYNSYM: "Minimal dynamic linking symbol table.",
            cls.SHT_INIT_ARRAY: "Pointers to initialization functions.",
            cls.SHT_FINI_ARRAY: "Pointers to termination functions.",
            cls.SHT_PREINIT_ARRAY: "Pointers to pre-initialization functions.",
            cls.SHT_LOPROC: "Start of processor-specific range.",
            cls.SHT_HIPROC: "End of processor-specific range.",
            cls.SHT_LOUSER: "Start of application-specific range.",
            cls.SHT_HIUSER: "End of application-specific range.",
            cls.SHT_GNU_VERDEF: "GNU version definitions provided.",
            cls.SHT_GNU_VERNEED: "GNU version requirements needed.",
            cls.SHT_GNU_VERSYM: "GNU version symbol table.",
        }

    def describe(self: SectionType) -> str:
        """Returns a human-readable description of the section type."""
        return self._description_map().get(self, "Unknown section type.")

    @classmethod
    def from_value(cls, value: int) -> SectionType:
        """Return a SectionType for the given integer value, creating a pseudo member if unknown.

        Args:
            value (int): Raw integer value of the section type field from the ELF header.

        Returns:
            SectionType: A real enum member if value is defined, otherwise a pseudo member
                whose name is formatted as UNKNOWN_0xXXXXXXXX preserving the original value.
        """
        try:
            return cls(value)
        except ValueError:
            # Create a pseudo enum instance preserving the integer (helps forward compatibility)
            pseudo = int.__new__(cls, value)
            pseudo._name_ = f"UNKNOWN_0x{value:08X}"
            pseudo._value_ = value
            return pseudo


class Section:
    """Represents a section in an ELF file."""

    def __init__(
        self: Section,
        name: str,
        section_type_val: int,
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
            section_type_val (int): The int type of the section from the define (e.g., SHT_PROGBITS, SHT_SYMTAB).
            flags (str): The flags associated with the section (e.g., X, W, R).
            address (int): The virtual address of the section in memory.
            offset (int): The offset of the section in the file.
            size (int): The size of the section in bytes.
            address_align (int): The required alignment of the section.
            reference_file (str): The path to the ELF file containing this section.
        """
        self.name = name
        self.section_type = SectionType.from_value(section_type_val)
        self.flags = flags
        self.start = address
        self.end = address + size
        self.offset = offset
        self.size = size
        self.address_align = address_align
        self.reference_file = reference_file

    def __repr__(self: Section) -> str:
        """Return a developer-oriented string representation of the Section."""
        return (
            f'Section(name="{self.name}", section_type={self.section_type.name}, flags={self.flags}, '
            f'address={self.start:#x}, offset={self.offset:#x}, size={self.size:#x}, '
            f'reference_file="{self.reference_file}")'
        )
