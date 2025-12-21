#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, TypeVar

if TYPE_CHECKING:
    from libdebug.data.registers import Registers

AccessorType = TypeVar("AccessorType", bound="BitfieldRegisterAccessor")


class BitfieldRegisterAccessor:
    """Base helper that exposes a register with bitfield helpers."""

    __slots__ = ("_bit_mask", "_register_name", "_registers")
    _repr_name = "Bitfield"
    BIT_FIELDS: ClassVar[dict[str, tuple[int, int]]] = {}

    def __init__(self: BitfieldRegisterAccessor, registers: Registers, register_name: str, bit_width: int) -> None:
        """Bind the accessor to the provided register set."""
        self._registers = registers
        self._register_name = register_name
        self._bit_mask = (1 << bit_width) - 1

    def __repr__(self: BitfieldRegisterAccessor) -> str:
        """Return a detailed representation of the bitfield."""
        summary = self._describe()
        if summary:
            return f"{self._repr_name}({int(self):#x}; {summary})"
        return f"{self._repr_name}({int(self):#x})"

    def __str__(self: BitfieldRegisterAccessor) -> str:
        """Return the hexadecimal representation of the bitfield."""
        return f"{int(self):#x}"

    def __format__(self: BitfieldRegisterAccessor, format_spec: str) -> str:
        """Format the bitfield according to the provided specifier."""
        return format(int(self), format_spec)

    def __int__(self: BitfieldRegisterAccessor) -> int:
        """Return the register value as an integer."""
        return self._read_raw()

    def __index__(self: BitfieldRegisterAccessor) -> int:
        """Allow direct usage in slicing or other index contexts."""
        return self._read_raw()

    def __eq__(self: BitfieldRegisterAccessor, other: object) -> bool:
        """Compare the register value against ints or other accessors."""
        if isinstance(other, BitfieldRegisterAccessor):
            return int(self) == int(other)
        if isinstance(other, int):
            return int(self) == other
        raise NotImplementedError(f"Cannot compare {type(self)} against {type(other)}")

    def _read_raw(self: BitfieldRegisterAccessor) -> int:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        return getattr(registers.register_file, self._register_name) & self._bit_mask

    def _write_raw(self: BitfieldRegisterAccessor, value: int) -> None:
        if not isinstance(value, int) or (value & ~self._bit_mask):
            raise ValueError(f"Value {value} does not fit in the bitfield mask {self._bit_mask:#x}")
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        setattr(registers.register_file, self._register_name, value & self._bit_mask)

    @property
    def value(self: BitfieldRegisterAccessor) -> int:
        """Return the raw value of the backing register."""
        return self._read_raw()

    @value.setter
    def value(self: BitfieldRegisterAccessor, new_value: int) -> None:
        """Overwrite the backing register with a raw value."""
        if not isinstance(new_value, int):
            raise TypeError(f"Cannot set bitfield value with value of type {type(new_value)}")
        self._write_raw(new_value)

    def _describe(self: BitfieldRegisterAccessor) -> str:
        """Return a compact textual description of non-zero bitfields."""
        entries: list[str] = []
        raw_value = self._read_raw()
        for name, (bit, width) in self.BIT_FIELDS.items():
            mask = (1 << width) - 1
            value = (raw_value >> bit) & mask
            if width == 1:
                if value:
                    entries.append(name)
            elif value:
                entries.append(f"{name}={value:#x}")
        return ", ".join(entries)


def _build_bitfield_property_by_name(field_name: str) -> property:
    """Build a property that looks up bit position and width from BIT_FIELDS at runtime."""

    def getter(self: BitfieldRegisterAccessor) -> int:
        # Look up the field metadata from BIT_FIELDS
        if field_name not in self.BIT_FIELDS:
            raise AttributeError(f"Field {field_name} not found in BIT_FIELDS")
        bit, width = self.BIT_FIELDS[field_name]
        mask = (1 << width) - 1
        return self._read_raw() >> bit & mask

    def setter(self: BitfieldRegisterAccessor, value: int | bool) -> None:
        if not isinstance(value, int | bool):
            raise TypeError(f"Cannot set field {field_name} with value of type {type(value)}")
        # Look up the field metadata from BIT_FIELDS
        if field_name not in self.BIT_FIELDS:
            raise AttributeError(f"Field {field_name} not found in BIT_FIELDS")
        bit, width = self.BIT_FIELDS[field_name]
        mask = (1 << width) - 1
        value_int = int(value)
        if not 0 <= value_int <= mask:
            raise ValueError(f"Value {value_int} does not fit in a {width}-bit flag")
        raw_value = self._read_raw()
        raw_value &= ~(mask << bit)
        raw_value |= (value_int & mask) << bit
        self._write_raw(raw_value)

    return property(getter, setter, None, f"bitfield_{field_name}")


def _build_register_accessor_property(
    register_name: str,
    bit_width: int,
    accessor_type: type[AccessorType],
) -> property:
    mask = (1 << bit_width) - 1

    def getter(registers: Registers) -> AccessorType:
        registers._internal_debugger._ensure_process_stopped_regs()
        return accessor_type(registers, register_name, bit_width)

    def setter(registers: Registers, value: int | BitfieldRegisterAccessor | bool) -> None:
        registers._internal_debugger._ensure_process_stopped_regs()
        if isinstance(value, BitfieldRegisterAccessor | bool):
            raw_value = int(value)
        elif isinstance(value, int):
            raw_value = value
        else:
            raise TypeError(f"Cannot set register {register_name} with value of type {type(value)}")
        if not 0 <= raw_value <= mask:
            raise ValueError(f"Value {value} does not fit in the register mask {mask:#x}")
        setattr(registers.register_file, register_name, raw_value & mask)

    return property(getter, setter, None, register_name)


class X86FlagsAccessor(BitfieldRegisterAccessor):
    """Expose the x86 FLAGS register as both an int and attribute-backed bitfields."""

    __slots__ = ()
    _repr_name = "Flags"

    BIT_FIELDS: ClassVar[dict[str, tuple[int, int]]] = {
        "CF": (0, 1),
        "PF": (2, 1),
        "AF": (4, 1),
        "ZF": (6, 1),
        "SF": (7, 1),
        "TF": (8, 1),
        "IF": (9, 1),
        "DF": (10, 1),
        "OF": (11, 1),
        "IOPL": (12, 2),
        "NT": (14, 1),
        "RF": (16, 1),
        "VM": (17, 1),
        "AC": (18, 1),
        "VIF": (19, 1),
        "VIP": (20, 1),
        "ID": (21, 1),
    }

    CF = _build_bitfield_property_by_name("CF")
    PF = _build_bitfield_property_by_name("PF")
    AF = _build_bitfield_property_by_name("AF")
    ZF = _build_bitfield_property_by_name("ZF")
    SF = _build_bitfield_property_by_name("SF")
    TF = _build_bitfield_property_by_name("TF")
    IF = _build_bitfield_property_by_name("IF")
    DF = _build_bitfield_property_by_name("DF")
    OF = _build_bitfield_property_by_name("OF")
    IOPL = _build_bitfield_property_by_name("IOPL")
    NT = _build_bitfield_property_by_name("NT")
    RF = _build_bitfield_property_by_name("RF")
    VM = _build_bitfield_property_by_name("VM")
    AC = _build_bitfield_property_by_name("AC")
    VIF = _build_bitfield_property_by_name("VIF")
    VIP = _build_bitfield_property_by_name("VIP")
    ID = _build_bitfield_property_by_name("ID")


class ArmPstateAccessor(BitfieldRegisterAccessor):
    """Expose the aarch64 PSTATE register with named bitfields."""

    __slots__ = ()
    _repr_name = "PState"

    BIT_FIELDS: ClassVar[dict[str, tuple[int, int]]] = {
        "N": (31, 1),
        "Z": (30, 1),
        "C": (29, 1),
        "V": (28, 1),
        "TCO": (25, 1),
        "DIT": (24, 1),
        "UAO": (23, 1),
        "PAN": (22, 1),
        "SS": (21, 1),
        "IL": (20, 1),
        "SSBS": (12, 1),
        "BTYPE": (10, 2),
        "D": (9, 1),
        "A": (8, 1),
        "I": (7, 1),
        "F": (6, 1),
        "M": (0, 5),
    }

    N = _build_bitfield_property_by_name("N")
    Z = _build_bitfield_property_by_name("Z")
    C = _build_bitfield_property_by_name("C")
    V = _build_bitfield_property_by_name("V")
    TCO = _build_bitfield_property_by_name("TCO")
    DIT = _build_bitfield_property_by_name("DIT")
    UAO = _build_bitfield_property_by_name("UAO")
    PAN = _build_bitfield_property_by_name("PAN")
    SS = _build_bitfield_property_by_name("SS")
    IL = _build_bitfield_property_by_name("IL")
    SSBS = _build_bitfield_property_by_name("SSBS")
    BTYPE = _build_bitfield_property_by_name("BTYPE")
    D = _build_bitfield_property_by_name("D")
    A = _build_bitfield_property_by_name("A")
    I = _build_bitfield_property_by_name("I")  # noqa: E741 - architectural name
    F = _build_bitfield_property_by_name("F")
    M = _build_bitfield_property_by_name("M")


def build_x86_flags_property(register_name: str, bit_width: int) -> property:
    """Return a property exposing the FLAGS register with bitfield helpers."""
    return _build_register_accessor_property(register_name, bit_width, X86FlagsAccessor)


def build_aarch64_pstate_property(register_name: str) -> property:
    """Return a property exposing the PSTATE register with bitfield helpers."""
    return _build_register_accessor_property(register_name, 64, ArmPstateAccessor)
