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


@dataclass
class Amd64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an x86_64 process."""

    def provide_regs_class(self: Amd64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return Amd64Registers

    def apply_on_regs(self: Amd64PtraceRegisterHolder, target: Amd64Registers, target_class: type) -> None:
        """Apply the register accessors to the Amd64Registers class."""
        target.register_file = self.register_file

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
