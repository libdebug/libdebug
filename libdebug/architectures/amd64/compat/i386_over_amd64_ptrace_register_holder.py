#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    _get_property_8h,
    _get_property_8l,
    _get_property_16,
    _get_property_32,
)
from libdebug.architectures.amd64.compat.i386_over_amd64_registers import I386OverAMD64Registers
from libdebug.architectures.i386.i386_ptrace_register_holder import (
    I386_BASE_REGS,
    I386_GP_REGS,
    I386_SPECIAL_REGS,
    I386PtraceRegisterHolder,
)

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


@dataclass
class I386OverAMD64PtraceRegisterHolder(I386PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an x86_64 process."""

    def provide_regs_class(self: I386OverAMD64PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return I386OverAMD64Registers

    def apply_on_regs(
        self: I386OverAMD64PtraceRegisterHolder,
        target: I386OverAMD64Registers,
        target_class: type,
    ) -> None:
        """Apply the register accessors to the I386Registers class."""
        target.register_file = self.register_file
        target._fp_register_file = self.fp_register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "eip"):
            return

        self._vector_fp_registers = []

        # setup accessors
        for name in I386_GP_REGS:
            name_64 = "r" + name + "x"
            name_32 = "e" + name + "x"
            name_16 = name + "x"
            name_8l = name + "l"
            name_8h = name + "h"

            setattr(target_class, name_32, _get_property_32(name_64))
            setattr(target_class, name_16, _get_property_16(name_64))
            setattr(target_class, name_8l, _get_property_8l(name_64))
            setattr(target_class, name_8h, _get_property_8h(name_64))

        for name in I386_BASE_REGS:
            name_64 = "r" + name
            name_32 = "e" + name
            name_16 = name
            name_8l = name + "l"

            setattr(target_class, name_32, _get_property_32(name_64))
            setattr(target_class, name_16, _get_property_16(name_64))
            setattr(target_class, name_8l, _get_property_8l(name_64))

        for name in I386_SPECIAL_REGS:
            setattr(target_class, name, _get_property_32(name))

        # setup special registers
        target_class.eip = _get_property_32("rip")

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

        I386OverAMD64PtraceRegisterHolder._vector_fp_registers = self._vector_fp_registers

    def apply_on_thread(self: I386OverAMD64PtraceRegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Apply the register accessors to the thread class."""
        target.register_file = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        # setup generic "instruction_pointer" property
        target_class.instruction_pointer = _get_property_32("rip")

        # setup generic syscall properties
        target_class.syscall_number = _get_property_32("orig_rax")
        target_class.syscall_return = _get_property_32("rax")
        target_class.syscall_arg0 = _get_property_32("rbx")
        target_class.syscall_arg1 = _get_property_32("rcx")
        target_class.syscall_arg2 = _get_property_32("rdx")
        target_class.syscall_arg3 = _get_property_32("rsi")
        target_class.syscall_arg4 = _get_property_32("rdi")
        target_class.syscall_arg5 = _get_property_32("rbp")

    def cleanup(self: I386OverAMD64PtraceRegisterHolder) -> None:
        """Clean up the register accessors from the I386OverAMD64Registers class."""
        for attr_name, attr_value in list(I386OverAMD64Registers.__dict__.items()):
            if isinstance(attr_value, property):
                delattr(I386OverAMD64Registers, attr_name)
