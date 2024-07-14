#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.architectures.aarch64.aarch64_registers import Aarch64Registers
from libdebug.ptrace.ptrace_register_holder import PtraceRegisterHolder

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

AARCH64_GP_REGS = ["x", "w"]


def _get_property_64(name: str) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name)

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        setattr(self.register_file, name, value)

    return property(getter, setter, None, name)


def _get_property_32(name: str) -> property:
    def getter(self: Aarch64Registers) -> int:
        self._internal_debugger._ensure_process_stopped()
        return getattr(self.register_file, name) & 0xFFFFFFFF

    def setter(self: Aarch64Registers, value: int) -> None:
        self._internal_debugger._ensure_process_stopped()
        return setattr(self.register_file, name, value & 0xFFFFFFFF)

    return property(getter, setter, None, name)


@dataclass
class Aarch64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the register of an aarch64 process."""

    def provide_regs_class(self: Aarch64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return Aarch64Registers

    def apply_on_regs(self: Aarch64PtraceRegisterHolder, target: Aarch64Registers, target_class: type) -> None:
        """Apply the register accessors to the Aarch64Registers class."""
        target.register_file = self.register_file

        if hasattr(target_class, "w0"):
            return

        for i in range(31):
            name_64 = f"w{i}"
            name_32 = f"x{i}"

            setattr(target_class, name_64, _get_property_64(name_64))
            setattr(target_class, name_32, _get_property_32(name_32))

        target_class.pc = _get_property_64("pc")

    def apply_on_thread(self: Aarch64PtraceRegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Apply the register accessors to the thread class."""
        target.register_file = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        # setup generic "instruction_pointer" property
        target_class.instruction_pointer = _get_property_64("pc")

        # setup generic syscall properties
        target_class.syscall_number = _get_property_64("x8")
        target_class.syscall_return = _get_property_64("x0")
        target_class.syscall_arg0 = _get_property_64("x0")
        target_class.syscall_arg1 = _get_property_64("x1")
        target_class.syscall_arg2 = _get_property_64("x2")
        target_class.syscall_arg3 = _get_property_64("x3")
        target_class.syscall_arg4 = _get_property_64("x4")
        target_class.syscall_arg5 = _get_property_64("x5")
