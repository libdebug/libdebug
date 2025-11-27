#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.registers import Registers


def _build_flag_property(bit: int, width: int = 1) -> property:
    mask = (1 << width) - 1

    def getter(self: X86FlagsAccessor) -> int:
        return self._read_raw() >> bit & mask

    def setter(self: X86FlagsAccessor, value: int | bool) -> None:
        value_int = (1 if value else 0) if isinstance(value, bool) else int(value)
        if value_int < 0 or value_int > mask:
            raise ValueError(f"Value {value_int} does not fit in a {width}-bit flag")

        raw_value = self._read_raw()
        raw_value &= ~(mask << bit)
        raw_value |= (value_int & mask) << bit
        self._write_raw(raw_value)

    return property(getter, setter, None, f"bitfield_{bit}")


class X86FlagsAccessor:
    """Helper that exposes the x86 FLAGS register both as an int and via flag attributes."""

    __slots__ = ("_bit_mask", "_register_name", "_registers")

    def __init__(self, registers: Registers, register_name: str, bit_width: int) -> None:
        """Bind the accessor to a register set and backing register name."""
        self._registers = registers
        self._register_name = register_name
        self._bit_mask = (1 << bit_width) - 1

    def __repr__(self) -> str:
        """Return a developer-friendly representation of the FLAGS value."""
        return f"Flags({int(self):#x})"

    def __str__(self) -> str:
        """Return the hex representation of the FLAGS register."""
        return f"{int(self):#x}"

    def __format__(self, format_spec: str) -> str:
        """Format the FLAGS value according to the provided specifier."""
        return format(int(self), format_spec)

    def __int__(self) -> int:
        """Return the current FLAGS value as an integer."""
        return self._read_raw()

    def __index__(self) -> int:
        """Allow use of the accessor wherever an index is required."""
        return self._read_raw()

    def __eq__(self, other: object) -> bool:
        """Compare FLAGS values against ints or other accessors."""
        if isinstance(other, X86FlagsAccessor):
            return int(self) == int(other)
        if isinstance(other, int):
            return int(self) == other
        return NotImplemented

    def _read_raw(self) -> int:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        return int(getattr(registers.register_file, self._register_name)) & self._bit_mask

    def _write_raw(self, value: int) -> None:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        setattr(registers.register_file, self._register_name, int(value) & self._bit_mask)

    @property
    def value(self) -> int:
        """Return the raw FLAGS register value."""
        return self._read_raw()

    @value.setter
    def value(self, new_value: int) -> None:
        self._write_raw(new_value)

    CF = _build_flag_property(0)
    PF = _build_flag_property(2)
    AF = _build_flag_property(4)
    ZF = _build_flag_property(6)
    SF = _build_flag_property(7)
    TF = _build_flag_property(8)
    IF = _build_flag_property(9)
    DF = _build_flag_property(10)
    OF = _build_flag_property(11)
    IOPL = _build_flag_property(12, width=2)
    NT = _build_flag_property(14)
    RF = _build_flag_property(16)
    VM = _build_flag_property(17)
    AC = _build_flag_property(18)
    VIF = _build_flag_property(19)
    VIP = _build_flag_property(20)
    ID = _build_flag_property(21)


def build_x86_flags_property(register_name: str, bit_width: int) -> property:
    """Return a property exposing the FLAGS register with bitfield helpers."""
    mask = (1 << bit_width) - 1

    def getter(registers: Registers) -> X86FlagsAccessor:
        registers._internal_debugger._ensure_process_stopped_regs()
        return X86FlagsAccessor(registers, register_name, bit_width)

    def setter(registers: Registers, value: int | X86FlagsAccessor | bool) -> None:
        registers._internal_debugger._ensure_process_stopped_regs()
        raw_value = int(value)
        setattr(registers.register_file, register_name, raw_value & mask)

    return property(getter, setter, None, register_name)
