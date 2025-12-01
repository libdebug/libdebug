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
    BIT_FIELDS: ClassVar[tuple[tuple[str, int, int], ...]] = ()

    def __init__(self: BitfieldRegisterAccessor, registers: Registers, register_name: str, bit_width: int) -> None:
        """Bind the accessor to the provided register set."""
        self._registers = registers
        self._register_name = register_name
        self._bit_mask = (1 << bit_width) - 1

    def __repr__(self: BitfieldRegisterAccessor) -> str:
        """Return a detailed representation of the bitfield."""
        summary = self.describe()
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
        return int(getattr(registers.register_file, self._register_name)) & self._bit_mask

    def _write_raw(self: BitfieldRegisterAccessor, value: int) -> None:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        setattr(registers.register_file, self._register_name, int(value) & self._bit_mask)

    @property
    def value(self: BitfieldRegisterAccessor) -> int:
        """Return the raw value of the backing register."""
        return self._read_raw()

    @value.setter
    def value(self: BitfieldRegisterAccessor, new_value: int) -> None:
        """Overwrite the backing register with a raw value."""
        self._write_raw(new_value)

    def describe(self: BitfieldRegisterAccessor) -> str:
        """Return a compact textual description of non-zero bitfields."""
        entries: list[str] = []
        raw_value = self._read_raw()
        for name, bit, width in self.BIT_FIELDS:
            mask = (1 << width) - 1
            value = (raw_value >> bit) & mask
            if width == 1:
                if value:
                    entries.append(name)
            elif value:
                entries.append(f"{name}={value:#x}")
        return ", ".join(entries)


def _build_bitfield_property(bit: int, width: int = 1) -> property:
    mask = (1 << width) - 1

    def getter(self: BitfieldRegisterAccessor) -> int:
        return self._read_raw() >> bit & mask

    def setter(self: BitfieldRegisterAccessor, value: int | bool) -> None:
        value_int = (1 if value else 0) if isinstance(value, bool) else int(value)
        if value_int < 0 or value_int > mask:
            raise ValueError(f"Value {value_int} does not fit in a {width}-bit flag")

        raw_value = self._read_raw()
        raw_value &= ~(mask << bit)
        raw_value |= (value_int & mask) << bit
        self._write_raw(raw_value)

    return property(getter, setter, None, f"bitfield_{bit}")


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
        raw_value = int(value)
        setattr(registers.register_file, register_name, raw_value & mask)

    return property(getter, setter, None, register_name)


class X86FlagsAccessor(BitfieldRegisterAccessor):
    """Expose the x86 FLAGS register as both an int and attribute-backed bitfields."""

    __slots__ = ()
    _repr_name = "Flags"

    BIT_FIELDS: ClassVar[tuple[tuple[str, int, int], ...]] = (
        ("CF", 0, 1),
        ("PF", 2, 1),
        ("AF", 4, 1),
        ("ZF", 6, 1),
        ("SF", 7, 1),
        ("TF", 8, 1),
        ("IF", 9, 1),
        ("DF", 10, 1),
        ("OF", 11, 1),
        ("IOPL", 12, 2),
        ("NT", 14, 1),
        ("RF", 16, 1),
        ("VM", 17, 1),
        ("AC", 18, 1),
        ("VIF", 19, 1),
        ("VIP", 20, 1),
        ("ID", 21, 1),
    )

    CF = _build_bitfield_property(0)
    PF = _build_bitfield_property(2)
    AF = _build_bitfield_property(4)
    ZF = _build_bitfield_property(6)
    SF = _build_bitfield_property(7)
    TF = _build_bitfield_property(8)
    IF = _build_bitfield_property(9)
    DF = _build_bitfield_property(10)
    OF = _build_bitfield_property(11)
    IOPL = _build_bitfield_property(12, width=2)
    NT = _build_bitfield_property(14)
    RF = _build_bitfield_property(16)
    VM = _build_bitfield_property(17)
    AC = _build_bitfield_property(18)
    VIF = _build_bitfield_property(19)
    VIP = _build_bitfield_property(20)
    ID = _build_bitfield_property(21)


class ArmPstateAccessor(BitfieldRegisterAccessor):
    """Expose the aarch64 PSTATE register with named bitfields."""

    __slots__ = ()
    _repr_name = "PState"

    BIT_FIELDS: ClassVar[tuple[tuple[str, int, int], ...]] = (
        ("N", 31, 1),
        ("Z", 30, 1),
        ("C", 29, 1),
        ("V", 28, 1),
        ("TCO", 25, 1),
        ("DIT", 24, 1),
        ("UAO", 23, 1),
        ("PAN", 22, 1),
        ("SS", 21, 1),
        ("IL", 20, 1),
        ("SSBS", 12, 1),
        ("BTYPE", 10, 2),
        ("D", 9, 1),
        ("A", 8, 1),
        ("I", 7, 1),
        ("F", 6, 1),
        ("M", 0, 5),
    )

    N = _build_bitfield_property(31)
    Z = _build_bitfield_property(30)
    C = _build_bitfield_property(29)
    V = _build_bitfield_property(28)
    TCO = _build_bitfield_property(25)
    DIT = _build_bitfield_property(24)
    UAO = _build_bitfield_property(23)
    PAN = _build_bitfield_property(22)
    SS = _build_bitfield_property(21)
    IL = _build_bitfield_property(20)
    SSBS = _build_bitfield_property(12)
    BTYPE = _build_bitfield_property(10, width=2)
    D = _build_bitfield_property(9)
    A = _build_bitfield_property(8)
    I = _build_bitfield_property(7)  # noqa: E741 - architectural name
    F = _build_bitfield_property(6)
    M = _build_bitfield_property(0, width=5)


def build_x86_flags_property(register_name: str, bit_width: int) -> property:
    """Return a property exposing the FLAGS register with bitfield helpers."""
    return _build_register_accessor_property(register_name, bit_width, X86FlagsAccessor)


def build_aarch64_pstate_property(register_name: str) -> property:
    """Return a property exposing the PSTATE register with bitfield helpers."""
    return _build_register_accessor_property(register_name, 64, ArmPstateAccessor)
