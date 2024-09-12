#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

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
    "r15",
    "r14",
    "r13",
    "r12",
    "rbp",
    "rbx",
    "r11",
    "r10",
    "r9",
    "r8",
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "orig_rax",
    "rip",
    "cs",
    "eflags",
    "rsp",
    "ss",
    "fs_base",
    "gs_base",
    "ds",
    "es",
    "fs",
    "gs",
]


def _get_property_64(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name)

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_32(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name) & 0xFFFFFFFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        return setattr(self.register_file, name, value & 0xFFFFFFFF)

    return property(getter, setter, None, name)


def _get_property_16(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name) & 0xFFFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        value = getattr(self.register_file, name) & ~0xFFFF | (value & 0xFFFF)
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_8l(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name) & 0xFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        value = getattr(self.register_file, name) & ~0xFF | (value & 0xFF)
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_8h(name: str) -> property:
    def getter(self: Amd64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name) >> 8 & 0xFF

    def setter(self: Amd64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        value = getattr(self.register_file, name) & ~0xFF00 | (value & 0xFF) << 8
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_fp_xmm0(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.xmm0[index].data, "little")

    def setter(self: Amd64Registers, value: int) -> None:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        data = value.to_bytes(16, "little")
        self._fp_register_file.xmm0[index].data = data
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_ymm0(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        xmm0 = int.from_bytes(self._fp_register_file.xmm0[index].data, "little")
        ymm0 = int.from_bytes(self._fp_register_file.ymm0[index].data, "little")
        return (ymm0 << 128) | xmm0

    def setter(self: Amd64Registers, value: int) -> None:
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
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm0 = int.from_bytes(self._fp_register_file.zmm0[index].data, "little")
        ymm0 = int.from_bytes(self._fp_register_file.ymm0[index].data, "little")
        xmm0 = int.from_bytes(self._fp_register_file.xmm0[index].data, "little")
        return (zmm0 << 256) | (ymm0 << 128) | xmm0

    def setter(self: Amd64Registers, value: int) -> None:
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
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm1 = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")
        return zmm1 & ((1 << 128) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        # We do not clear the upper 384 bits of the register
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        previous_value = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")

        new_value = (previous_value & ~((1 << 128) - 1)) | (value & ((1 << 128) - 1))
        self._fp_register_file.zmm1[index].data = new_value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_ymm1(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        zmm1 = int.from_bytes(self._fp_register_file.zmm1[index].data, "little")
        return zmm1 & ((1 << 256) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        # We do not clear the upper 256 bits of the register
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        previous_value = self._fp_register_file.zmm1[index]

        new_value = (previous_value & ~((1 << 256) - 1)) | (value & ((1 << 256) - 1))
        self._fp_register_file.zmm1[index].data = new_value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


def _get_property_fp_zmm1(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.zmm1[index].data, "little")

    def setter(self: Amd64Registers, value: int) -> None:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.zmm1[index].data = value.to_bytes(64, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)

def _get_property_fp_mmx(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> int:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return int.from_bytes(self._fp_register_file.legacy.mmx[index].data, "little") & ((1 << 64) - 1)

    def setter(self: Amd64Registers, value: int) -> None:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.legacy.mmx[index].data = (value & ((1 << 64) - 1)).to_bytes(16, "little")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)

def _get_property_fp_st(name: str, index: int) -> property:
    def getter(self: Amd64Registers) -> float:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return self._fp_register_file.legacy.st[index]

    def setter(self: Amd64Registers, value: float) -> None:
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        self._fp_register_file.legacy.st[index] = value
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)

@dataclass
class Amd64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an x86_64 process."""

    def provide_regs_class(self: Amd64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return Amd64Registers

    def apply_on_regs(self: Amd64PtraceRegisterHolder, target: Amd64Registers, target_class: type) -> None:
        """Apply the register accessors to the Amd64Registers class."""
        target.register_file = self.register_file
        target._fp_register_file = self.fp_register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "rip"):
            return

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

        # setup special registers
        target_class.rip = _get_property_64("rip")

        # setup floating-point registers
        # see libdebug/cffi/ptrace_cffi_build.py for the possible values of fp_register_file.type
        self._handle_fp_legacy(target_class)

        match self.fp_register_file.type:
            case 0:
                self._handle_fp_512(target_class)
            case 1:
                self._handle_fp_896(target_class)
            case 2:
                self._handle_fp_2696(target_class)
            case _:
                raise NotImplementedError(
                    f"Floating-point register file type {self.fp_register_file.type} not available.",
                )

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
            name = f"mm{index}"
            setattr(target_class, name, _get_property_fp_mmx(name, index))

        for index in range(8):
            name = f"st{index}"
            setattr(target_class, name, _get_property_fp_st(name, index))

    def _handle_fp_512(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 512 bytes long, which means we just have the xmm registers."""
        for index in range(16):
            name = f"xmm{index}"
            setattr(target_class, name, _get_property_fp_xmm0(name, index))

    def _handle_fp_896(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 896 bytes long, which means we have the xmm and ymm registers."""
        for index in range(16):
            name = f"xmm{index}"
            setattr(target_class, name, _get_property_fp_xmm0(name, index))

        for index in range(16):
            name = f"ymm{index}"
            setattr(target_class, name, _get_property_fp_ymm0(name, index))

    def _handle_fp_2696(self: Amd64PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 2696 bytes long, which means we have 32 zmm registers."""
        for index in range(16):
            name = f"xmm{index}"
            setattr(target_class, name, _get_property_fp_xmm0(name, index))

        for index in range(16):
            name = f"ymm{index}"
            setattr(target_class, name, _get_property_fp_ymm0(name, index))

        for index in range(16):
            name = f"zmm{index}"
            setattr(target_class, name, _get_property_fp_zmm0(name, index))

        for index in range(16):
            name = f"xmm{index + 16}"
            setattr(target_class, name, _get_property_fp_xmm1(name, index))

        for index in range(16):
            name = f"ymm{index + 16}"
            setattr(target_class, name, _get_property_fp_ymm1(name, index))

        for index in range(16):
            name = f"zmm{index + 16}"
            setattr(target_class, name, _get_property_fp_zmm1(name, index))
