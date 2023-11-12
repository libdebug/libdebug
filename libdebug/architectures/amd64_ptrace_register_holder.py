#
# This file is part of libdebug Python library (https://github.com/gabriele180698/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from dataclasses import dataclass
from libdebug.architectures.register_holder import PtraceRegisterHolder
from libdebug.utils.packing_utils import u64, p64
from libdebug.utils.register_utils import (
    get_reg_64,
    get_reg_32,
    get_reg_16,
    get_reg_8l,
    get_reg_8h,
    set_reg_64,
    set_reg_32,
    set_reg_16,
    set_reg_8l,
    set_reg_8h,
)

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


@dataclass
class Amd64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an x86_64 process, specifically for the `ptrace` debugging backend."""

    def apply_on(self, target, target_class):
        target.regs = {}

        for i, name in enumerate(AMD64_REGS):
            target.regs[name] = u64(self.register_file[i * 8 : (i + 1) * 8])

        def get_property_64(name):
            def getter(self):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                return get_reg_64(self.regs, name)

            def setter(self, value):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                set_reg_64(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_32(name):
            def getter(self):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                return get_reg_32(self.regs, name)

            def setter(self, value):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                set_reg_32(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_16(name):
            def getter(self):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                return get_reg_16(self.regs, name)

            def setter(self, value):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                set_reg_16(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_8l(name):
            def getter(self):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                return get_reg_8l(self.regs, name)

            def setter(self, value):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                set_reg_8l(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_8h(name):
            def getter(self):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                return get_reg_8h(self.regs, name)

            def setter(self, value):
                if self.running:
                    raise RuntimeError(
                        "Cannot access registers while the process is running."
                    )
                set_reg_8h(self.regs, name, value)

            return property(getter, setter, None, name)

        # setup accessors
        for name in AMD64_GP_REGS:
            name_64 = "r" + name + "x"
            name_32 = "e" + name + "x"
            name_16 = name + "x"
            name_8l = name + "l"
            name_8h = name + "h"

            setattr(target_class, name_64, get_property_64(name_64))
            setattr(target_class, name_32, get_property_32(name_64))
            setattr(target_class, name_16, get_property_16(name_64))
            setattr(target_class, name_8l, get_property_8l(name_64))
            setattr(target_class, name_8h, get_property_8h(name_64))

        for name in AMD64_BASE_REGS:
            name_64 = "r" + name
            name_32 = "e" + name
            name_16 = name
            name_8l = name + "l"

            setattr(target_class, name_64, get_property_64(name_64))
            setattr(target_class, name_32, get_property_32(name_64))
            setattr(target_class, name_16, get_property_16(name_64))
            setattr(target_class, name_8l, get_property_8l(name_64))

        for name in AMD64_EXT_REGS:
            name_64 = name
            name_32 = name + "d"
            name_16 = name + "w"
            name_8l = name + "b"

            setattr(target_class, name_64, get_property_64(name_64))
            setattr(target_class, name_32, get_property_32(name_64))
            setattr(target_class, name_16, get_property_16(name_64))
            setattr(target_class, name_8l, get_property_8l(name_64))

        # setup special registers
        setattr(target_class, "rip", get_property_64("rip"))

    def flush(self, source):
        """Flushes the register values to the target process."""
        buffer = b""
        for name in AMD64_REGS:
            buffer += p64(source.regs[name])
        self.ptrace_setter(buffer)
