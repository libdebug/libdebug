#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from ctypes import c_longdouble
from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.architectures.amd64.amd64_registers import Amd64Registers
from libdebug.ptrace.ptrace_register_holder import PtraceRegisterHolder

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

AMD64_GP_REGS = ["a", "b", "c", "d"]

AMD64_BASE_REGS = ["bp", "sp", "si", "di"]

AMD64_EXT_REGS = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

AMD64_REGS = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rdi",
    "rsi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rbp",
    "rsp",
    "rip",
]

AMD64_SPECIAL_REGS = [
    "eflags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs",
    "fs_base",
    "gs_base",
]


def _get_property_64(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name)

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_32(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name) & 0xFFFFFFFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        return setattr(self.register_file, name, value & 0xFFFFFFFF)

    return property(getter, setter, None, name)


def _get_property_16(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name) & 0xFFFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        value = getattr(self.register_file, name) & ~0xFFFF | (value & 0xFFFF)
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_8l(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name) & 0xFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        value = getattr(self.register_file, name) & ~0xFF | (value & 0xFF)
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_8h(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name) >> 8 & 0xFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        value = getattr(self.register_file, name) & ~0xFF00 | (value & 0xFF) << 8
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _build_flag_property(bit: int, width: int = 1) -> property:
    mask = (1 << width) - 1

    def getter(self: EflagsAccessor) -> int:
        return self._read_raw() >> bit & mask

    def setter(self: EflagsAccessor, value: int | bool) -> None:
        value_int = (1 if value else 0) if isinstance(value, bool) else int(value)
        if value_int < 0 or value_int > mask:
            raise ValueError(f"Value {value_int} does not fit in a {width}-bit flag")

        raw_value = self._read_raw()
        raw_value &= ~(mask << bit)
        raw_value |= (value_int & mask) << bit
        self._write_raw(raw_value)

    return property(getter, setter, None, f"bitfield_{bit}")


class EflagsAccessor:
    """Helper that exposes the amd64 FLAGS register both as an int and via flag attributes."""

    __slots__ = ("_registers",)

    def __init__(self, registers: Amd64Registers) -> None:
        """Bind the accessor to the provided register set."""
        self._registers = registers

    def __repr__(self) -> str:
        """Return a developer-friendly representation of the FLAGS value."""
        return f"Eflags({int(self):#x})"

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
        if isinstance(other, EflagsAccessor):
            return int(self) == int(other)
        if isinstance(other, int):
            return int(self) == other
        return NotImplemented

    def _read_raw(self) -> int:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        return int(registers.register_file.eflags)

    def _write_raw(self, value: int) -> None:
        registers = self._registers
        registers._internal_debugger._ensure_process_stopped_regs()
        registers.register_file.eflags = int(value) & 0xFFFFFFFFFFFFFFFF

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


def _get_property_eflags() -> property:
    def getter(self: Amd64Registers) -> EflagsAccessor:
        self._internal_debugger._ensure_process_stopped_regs()
        return EflagsAccessor(self)

    def setter(self: Amd64Registers, value: int | EflagsAccessor) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        raw_value = int(value)
        self.register_file.eflags = raw_value & 0xFFFFFFFFFFFFFFFF

    return property(getter, setter, None, "eflags")


def _get_property_fp_xmm0(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.xmm0[index].data, "little")

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        data = value.to_bytes(16, "little")
        self._fp_register_file.xmm0[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_ymm0(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        xmm0 = int.from_bytes(self._fp_register_file.xmm0[index].data, "little")
        ymm0 = int.from_bytes(self._fp_register_file.ymm0[index].data, "little")
        return (ymm0 << 128) | xmm0

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        new_xmm0 = value & ((1 << 128) - 1)
        new_ymm0 = value >> 128
        self._fp_register_file.xmm0[index].data = new_xmm0.to_bytes(16, "little")
        self._fp_register_file.ymm0[index].data = new_ymm0.to_bytes(16, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_zmm0(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm0 = int.from_bytes(self._fp_register_file.zmm0[index].data, "little")
        ymm0 = int.from_bytes(self._fp_register_file.ymm0[index].data, "little")
        xmm0 = int.from_bytes(self._fp_register_file.xmm0[index].data, "little")
        return (zmm0 << 256) | (ymm0 << 128) | xmm0

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        new_xmm0 = value & ((1 << 128) - 1)
        new_ymm0 = (value >> 128) & ((1 << 128) - 1)
        new_zmm0 = value >> 256
        self._fp_register_file.xmm0[index].data = new_xmm0.to_bytes(16, "little")
        self._fp_register_file.ymm0[index].data = new_ymm0.to_bytes(16, "little")
        self._fp_register_file.zmm0[index].data = new_zmm0.to_bytes(32, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_xmm1(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm1 = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")
        return zmm1 & ((1 << 128) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        # We do not clear the upper 384 bits of the register
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        previous_value = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")

        new_value = (previous_value & ~((1 << 128) - 1)) | (value & ((1 << 128) - 1))
        self._fp_register_file.zmm1[index].data = new_value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_ymm1(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm1 = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")
        return zmm1 & ((1 << 256) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        # We do not clear the upper 256 bits of the register
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        previous_value = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")

        new_value = (previous_value & ~((1 << 256) - 1)) | (value & ((1 << 256) - 1))
        self._fp_register_file.zmm1[index].data = new_value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_zmm1(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.zmm1[index].data, "little")

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.zmm1[index].data = value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_mmx(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.mmx[index].data, "little") & ((1 << 64) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.mmx[index].data = (value & ((1 << 64) - 1)).to_bytes(16, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_st(name: str, index: int) -> property:
    # We should be able to expose the long double member from nanobind directly
    # But their support for long double does not actually allow for value comparison or manipulation
    # So, ctypes it is
    def getter(self: Amd64Registers) -> float:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return c_longdouble.from_buffer_copy(bytes(self._fp_register_file.mmx[index].data)).value

    def setter(self: Amd64Registers, value: float) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.mmx[index].data = bytes(c_longdouble(value))
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


@dataclass
class Amd64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an x86_64 process."""

    def provide_regs_class(self: Amd64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return Amd64Registers

    def provide_regs(self: Amd64PtraceRegisterHolder) -> list[str]:
        """Provide the list of registers, excluding the vector and fp registers."""
        return AMD64_REGS

    def provide_vector_fp_regs(self: Amd64PtraceRegisterHolder) -> list[tuple[str]]:
        """Provide the list of vector and floating point registers."""
        return self._vector_fp_registers

    def provide_special_regs(self: Amd64PtraceRegisterHolder) -> list[str]:
        """Provide the list of special registers, which are not intended for general-purpose use."""
        return AMD64_SPECIAL_REGS

    def apply_on_regs(self: Amd64PtraceRegisterHolder, target: Amd64Registers, target_class: type) -> None:
        """Apply the register accessors to the Amd64Registers class."""
        target.register_file = self.register_file
        target._fp_register_file = self.fp_register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "rip"):
            return

        self._vector_fp_registers = []

        # setup accessors
        for name in AMD64_GP_REGS:
            name_64 = "r" + name + "x"
            name_32 = "e" + name + "x"
            name_16 = name + "x"
            name_8l = name + "l"
            name_8h = name + "h"

            setattr(target_class, name_64, _get_property_64(name_64))
            setattr(target_class, name_32, _get_property_32(name_64))
            setattr(target_class, name_16, _get_property_16(name_64))
            setattr(target_class, name_8l, _get_property_8l(name_64))
            setattr(target_class, name_8h, _get_property_8h(name_64))

        for name in AMD64_BASE_REGS:
            name_64 = "r" + name
            name_32 = "e" + name
            name_16 = name
            name_8l = name + "l"

            setattr(target_class, name_64, _get_property_64(name_64))
            setattr(target_class, name_32, _get_property_32(name_64))
            setattr(target_class, name_16, _get_property_16(name_64))
            setattr(target_class, name_8l, _get_property_8l(name_64))

        for name in AMD64_EXT_REGS:
            name_64 = name
            name_32 = name + "d"
            name_16 = name + "w"
            name_8l = name + "b"

            setattr(target_class, name_64, _get_property_64(name_64))
            setattr(target_class, name_32, _get_property_32(name_64))
            setattr(target_class, name_16, _get_property_16(name_64))
            setattr(target_class, name_8l, _get_property_8l(name_64))

        for name in AMD64_SPECIAL_REGS:
            if name == "eflags":
                setattr(target_class, name, _get_property_eflags())
            else:
                setattr(target_class, name, _get_property_64(name))

        # setup special registers
        target_class.rip = _get_property_64("rip")

        # setup floating-point registers
        # see libdebug/cffi/ptrace_cffi_build.py for the possible values of fp_register_file.type
        self._handle_fp_legacy(target_class)

        match self.fp_register_file.type:
            case 0:
                self._handle_vector_512(target_class)
            case 1:
                self._handle_vector_896(target_class)
            case 2:
                self._handle_vector_2696(target_class)
            case _:
                raise NotImplementedError(
                    f"Floating-point register file type {self.fp_register_file.type} not available.",
                )

        Amd64PtraceRegisterHolder._vector_fp_registers = self._vector_fp_registers

    def apply_on_thread(self: Amd64PtraceRegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Apply the register accessors to the thread class."""
        target.register_file = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        # setup generic "instruction_pointer" property
        target_class.instruction_pointer = _get_property_64("rip")

        # setup generic syscall properties
        target_class.syscall_number = _get_property_64("orig_rax")
        target_class.syscall_return = _get_property_64("rax")
        target_class.syscall_arg0 = _get_property_64("rdi")
        target_class.syscall_arg1 = _get_property_64("rsi")
        target_class.syscall_arg2 = _get_property_64("rdx")
        target_class.syscall_arg3 = _get_property_64("r10")
        target_class.syscall_arg4 = _get_property_64("r8")
        target_class.syscall_arg5 = _get_property_64("r9")

    def _handle_fp_legacy(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle legacy mmx and st registers."""
        for index in range(8):
            name_mm = f"mm{index}"
            setattr(target_class, name_mm, _get_property_fp_mmx(name_mm, index))

            name_st = f"st{index}"
            setattr(target_class, name_st, _get_property_fp_st(name_st, index))

            self._vector_fp_registers.append((name_mm, name_st))

    def _handle_vector_512(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 512 bytes long, which means we just have the xmm registers."""
        for index in range(16):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))
            self._vector_fp_registers.append((name_xmm,))

    def _handle_vector_896(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 896 bytes long, which means we have the xmm and ymm registers."""
        for index in range(16):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))

            name_ymm = f"ymm{index}"
            setattr(target_class, name_ymm, _get_property_fp_ymm0(name_ymm, index))

            self._vector_fp_registers.append((name_xmm, name_ymm))

    def _handle_vector_2696(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 2696 bytes long, which means we have 32 zmm registers."""
        for index in range(16):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))

            name_ymm = f"ymm{index}"
            setattr(target_class, name_ymm, _get_property_fp_ymm0(name_ymm, index))

            name_zmm = f"zmm{index}"
            setattr(target_class, name_zmm, _get_property_fp_zmm0(name_zmm, index))

            self._vector_fp_registers.append((name_xmm, name_ymm, name_zmm))

        for index in range(16):
            name_xmm = f"xmm{index + 16}"
            setattr(target_class, name_xmm, _get_property_fp_xmm1(name_xmm, index))

            name_ymm = f"ymm{index + 16}"
            setattr(target_class, name_ymm, _get_property_fp_ymm1(name_ymm, index))

            name_zmm = f"zmm{index + 16}"
            setattr(target_class, name_zmm, _get_property_fp_zmm1(name_zmm, index))

            self._vector_fp_registers.append((name_xmm, name_ymm, name_zmm))
