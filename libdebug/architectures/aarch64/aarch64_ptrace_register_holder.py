#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.architectures.aarch64.aarch64_registers import Aarch64Registers
from libdebug.ptrace.ptrace_register_holder import PtraceRegisterHolder

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

AARCH64_REGS = [f"x{i}" for i in range(31)] + ["sp", "xzr", "pc"]

AARCH64_SPECIAL_REGS = ["pstate"]


def _get_property_64(name: str) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name)

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_32(name: str) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return getattr(self.register_file, name) & 0xFFFFFFFF

    # https://developer.arm.com/documentation/102374/0101/Registers-in-AArch64---general-purpose-registers
    # When a W register is written the top 32 bits of the 64-bit register are zeroed.
    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        return setattr(self.register_file, name, value & 0xFFFFFFFF)

    return property(getter, setter, None, name)


def _get_property_zr(name: str) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return 0

    def setter(self: Aarch64Registers, _: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()

    return property(getter, setter, None, name)


def _get_property_fp_8(name: str, index: int) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.vregs[index].data, sys.byteorder) & 0xFF

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)

        # The binding expects the value to be a 16-byte array, so we can't rely on to_bytes
        # to fail if the value is too large. We need to check it manually and then dump it
        # to a 16-byte array.
        if (value & 0xFF) != value:
            raise ValueError("Value is too large for 8-bit register")

        data = value.to_bytes(16, sys.byteorder)
        self._fp_register_file.vregs[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_16(name: str, index: int) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.vregs[index].data, sys.byteorder) & 0xFFFF

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)

        # The binding expects the value to be a 16-byte array, so we can't rely on to_bytes
        # to fail if the value is too large. We need to check it manually and then dump it
        # to a 16-byte array.
        if (value & 0xFFFF) != value:
            raise ValueError("Value is too large for 16-bit register")

        data = value.to_bytes(16, sys.byteorder)
        self._fp_register_file.vregs[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_32(name: str, index: int) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.vregs[index].data, sys.byteorder) & 0xFFFFFFFF

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)

        # The binding expects the value to be a 16-byte array, so we can't rely on to_bytes
        # to fail if the value is too large. We need to check it manually and then dump it
        # to a 16-byte array.
        if (value & 0xFFFFFFFF) != value:
            raise ValueError("Value is too large for 32-bit register")

        data = value.to_bytes(16, sys.byteorder)
        self._fp_register_file.vregs[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_64(name: str, index: int) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.vregs[index].data, sys.byteorder) & 0xFFFFFFFFFFFFFFFF

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)

        # The binding expects the value to be a 16-byte array, so we can't rely on to_bytes
        # to fail if the value is too large. We need to check it manually and then dump it
        # to a 16-byte array.
        if (value & 0xFFFFFFFFFFFFFFFF) != value:
            raise ValueError("Value is too large for 64-bit register")

        data = value.to_bytes(16, sys.byteorder)
        self._fp_register_file.vregs[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_128(name: str, index: int) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.vregs[index].data, sys.byteorder)

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        data = value.to_bytes(16, sys.byteorder)
        self._fp_register_file.vregs[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_syscall_num() -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped_regs()
        return self.register_file.x8

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped_regs()
        self.register_file.x8 = value
        self.register_file.override_syscall_number = True

    return property(getter, setter, None, "syscall_number")


@dataclass
class Aarch64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the register of an aarch64 process."""

    def provide_regs_class(self: Aarch64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return Aarch64Registers

    def provide_regs(self: Aarch64PtraceRegisterHolder) -> list[str]:
        """Provide the list of registers, excluding the vector and fp registers."""
        return AARCH64_REGS

    def provide_vector_fp_regs(self: Aarch64PtraceRegisterHolder) -> list[tuple[str]]:
        """Provide the list of vector and floating point registers."""
        return self._vector_fp_registers

    def provide_special_regs(self: Aarch64PtraceRegisterHolder) -> list[str]:
        """Provide the list of special registers, which are not intended for general-purpose use."""
        return AARCH64_SPECIAL_REGS

    def apply_on_regs(self: Aarch64PtraceRegisterHolder, target: Aarch64Registers, target_class: type) -> None:
        """Apply the register accessors to the Aarch64Registers class."""
        target.register_file = self.register_file
        target._fp_register_file = self.fp_register_file

        if hasattr(target_class, "w0"):
            return

        self._vector_fp_registers = []

        for i in range(31):
            name_64 = f"x{i}"
            name_32 = f"w{i}"

            setattr(target_class, name_64, _get_property_64(name_64))
            setattr(target_class, name_32, _get_property_32(name_64))

        for reg in AARCH64_SPECIAL_REGS:
            setattr(target_class, reg, _get_property_64(reg))

        # setup the floating point registers
        for i in range(32):
            name_v = f"v{i}"
            name_128 = f"q{i}"
            name_64 = f"d{i}"
            name_32 = f"s{i}"
            name_16 = f"h{i}"
            name_8 = f"b{i}"
            setattr(target_class, name_v, _get_property_fp_128(name_v, i))
            setattr(target_class, name_128, _get_property_fp_128(name_128, i))
            setattr(target_class, name_64, _get_property_fp_64(name_64, i))
            setattr(target_class, name_32, _get_property_fp_32(name_32, i))
            setattr(target_class, name_16, _get_property_fp_16(name_16, i))
            setattr(target_class, name_8, _get_property_fp_8(name_8, i))
            self._vector_fp_registers.append((name_v, name_128, name_64, name_32, name_16, name_8))

        # setup special aarch64 registers
        target_class.pc = _get_property_64("pc")
        target_class.sp = _get_property_64("sp")
        target_class.lr = _get_property_64("x30")
        target_class.fp = _get_property_64("x29")
        target_class.xzr = _get_property_zr("xzr")
        target_class.wzr = _get_property_zr("wzr")

        Aarch64PtraceRegisterHolder._vector_fp_registers = self._vector_fp_registers

    def apply_on_thread(self: Aarch64PtraceRegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Apply the register accessors to the thread class."""
        target.register_file = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        # setup generic "instruction_pointer" property
        target_class.instruction_pointer = _get_property_64("pc")

        # setup generic syscall properties
        target_class.syscall_return = _get_property_64("x0")
        target_class.syscall_arg0 = _get_property_64("x0")
        target_class.syscall_arg1 = _get_property_64("x1")
        target_class.syscall_arg2 = _get_property_64("x2")
        target_class.syscall_arg3 = _get_property_64("x3")
        target_class.syscall_arg4 = _get_property_64("x4")
        target_class.syscall_arg5 = _get_property_64("x5")

        # syscall number handling is special on aarch64, as the original number is stored in x8
        # but writing to x8 isn't enough to change the actual called syscall
        target_class.syscall_number = _get_property_syscall_num()

    def cleanup(self: Aarch64PtraceRegisterHolder) -> None:
        """Clean up the register accessors from the Aarch64Registers class."""
        for attr_name, attr_value in list(Aarch64Registers.__dict__.items()):
            if isinstance(attr_value, property):
                delattr(Aarch64Registers, attr_name)
