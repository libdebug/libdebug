#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from ctypes import c_longdouble
from dataclasses import dataclass
from typing import TYPE_CHECKING

from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    _get_property_8h,
    _get_property_8l,
    _get_property_16,
    _get_property_32,
    _get_property_fp_mmx,
    _get_property_fp_xmm0,
    _get_property_fp_ymm0,
    _get_property_fp_zmm0,
)
from libdebug.architectures.i386.i386_registers import I386Registers
from libdebug.ptrace.ptrace_register_holder import PtraceRegisterHolder

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext

I386_GP_REGS = ["a", "b", "c", "d"]

I386_BASE_REGS = ["bp", "sp", "si", "di"]

I386_REGS = [
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "eip",
]

I386_SPECIAL_REGS = [
    "eflags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs",
]


# We cannot recycle this function from the amd64 version because the c_longdouble returns a 12-byte array
# instead of a 16-byte array, which the nanobind binding does not expect.
# We need to reimplement it here.
def _get_property_fp_st(name: str, index: int) -> property:
    # We should be able to expose the long double member from nanobind directly
    # But their support for long double does not actually allow for value comparison or manipulation
    # So, ctypes it is
    def getter(self: I386Registers) -> float:
        self._internal_debugger._ensure_process_stopped()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        return c_longdouble.from_buffer_copy(bytes(self._fp_register_file.mmx[index].data)).value

    def setter(self: I386Registers, value: float) -> None:
        self._internal_debugger._ensure_process_stopped()
        if not self._fp_register_file.fresh:
            self._internal_debugger._fetch_fp_registers(self)
        # Only difference from the amd64 version is the padding to 16 bytes
        self._fp_register_file.mmx[index].data = bytes(c_longdouble(value)).ljust(16, b"\x00")
        self._fp_register_file.dirty = True

    return property(getter, setter, None, name)


@dataclass
class I386PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an i386 process."""

    def provide_regs_class(self: I386PtraceRegisterHolder) -> type:
        """Provide a class to hold the register accessors."""
        return I386Registers

    def provide_regs(self: I386PtraceRegisterHolder) -> list[str]:
        """Provide the list of registers, excluding the vector and fp registers."""
        return I386_REGS

    def provide_vector_fp_regs(self: I386PtraceRegisterHolder) -> list[str]:
        """Provide the list of vector and floating point registers."""
        return self._vector_fp_registers

    def provide_special_regs(self: I386PtraceRegisterHolder) -> list[str]:
        """Provide the list of special registers, which are not intended for general-purpose use."""
        return I386_SPECIAL_REGS

    def apply_on_regs(self: I386PtraceRegisterHolder, target: I386Registers, target_class: type) -> None:
        """Apply the register accessors to the I386Registers class."""
        target.register_file = self.register_file
        target._fp_register_file = self.fp_register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "eip"):
            return

        self._vector_fp_registers = []

        # setup accessors
        for name in I386_GP_REGS:
            name_32 = "e" + name + "x"
            name_16 = name + "x"
            name_8l = name + "l"
            name_8h = name + "h"

            setattr(target_class, name_32, _get_property_32(name_32))
            setattr(target_class, name_16, _get_property_16(name_32))
            setattr(target_class, name_8l, _get_property_8l(name_32))
            setattr(target_class, name_8h, _get_property_8h(name_32))

        for name in I386_BASE_REGS:
            name_32 = "e" + name
            name_16 = name
            name_8l = name + "l"

            setattr(target_class, name_32, _get_property_32(name_32))
            setattr(target_class, name_16, _get_property_16(name_32))
            setattr(target_class, name_8l, _get_property_8l(name_32))

        for name in I386_SPECIAL_REGS:
            setattr(target_class, name, _get_property_32(name))

        # setup special registers
        target_class.eip = _get_property_32("eip")

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

        I386PtraceRegisterHolder._vector_fp_registers = self._vector_fp_registers

    def apply_on_thread(self: I386PtraceRegisterHolder, target: ThreadContext, target_class: type) -> None:
        """Apply the register accessors to the thread class."""
        target.register_file = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        # setup generic "instruction_pointer" property
        target_class.instruction_pointer = _get_property_32("eip")

        # setup generic syscall properties
        target_class.syscall_number = _get_property_32("orig_eax")
        target_class.syscall_return = _get_property_32("eax")
        target_class.syscall_arg0 = _get_property_32("ebx")
        target_class.syscall_arg1 = _get_property_32("ecx")
        target_class.syscall_arg2 = _get_property_32("edx")
        target_class.syscall_arg3 = _get_property_32("esi")
        target_class.syscall_arg4 = _get_property_32("edi")
        target_class.syscall_arg5 = _get_property_32("ebp")

    def _handle_fp_legacy(self: I386PtraceRegisterHolder, target_class: type) -> None:
        """Handle legacy mmx and st registers."""
        for index in range(8):
            name_mm = f"mm{index}"
            setattr(target_class, name_mm, _get_property_fp_mmx(name_mm, index))

            name_st = f"st{index}"
            setattr(target_class, name_st, _get_property_fp_st(name_st, index))

            self._vector_fp_registers.append((name_mm, name_st))

    def _handle_vector_512(self: I386PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 512 bytes long, which means we just have the xmm registers."""
        # i386 only gets 8 registers
        for index in range(8):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))
            self._vector_fp_registers.append((name_xmm,))

    def _handle_vector_896(self: I386PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 896 bytes long, which means we have the xmm and ymm registers."""
        # i386 only gets 8 registers
        for index in range(8):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))

            name_ymm = f"ymm{index}"
            setattr(target_class, name_ymm, _get_property_fp_ymm0(name_ymm, index))

            self._vector_fp_registers.append((name_xmm, name_ymm))

    def _handle_vector_2696(self: I386PtraceRegisterHolder, target_class: type) -> None:
        """Handle the case where the xsave area is 2696 bytes long, which means we have 32 zmm registers."""
        # i386 only gets 8 registers
        for index in range(8):
            name_xmm = f"xmm{index}"
            setattr(target_class, name_xmm, _get_property_fp_xmm0(name_xmm, index))

            name_ymm = f"ymm{index}"
            setattr(target_class, name_ymm, _get_property_fp_ymm0(name_ymm, index))

            name_zmm = f"zmm{index}"
            setattr(target_class, name_zmm, _get_property_fp_zmm0(name_zmm, index))

            self._vector_fp_registers.append((name_xmm, name_ymm, name_zmm))

    def cleanup(self: I386PtraceRegisterHolder) -> None:
        """Clean up the register accessors from the class."""
        for attr_name, attr_value in list(I386Registers.__dict__.items()):
            if isinstance(attr_value, property):
                delattr(I386Registers, attr_name)
