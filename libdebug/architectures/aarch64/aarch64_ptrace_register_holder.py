#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.register_holder import PtraceRegisterHolder
from libdebug.utils.register_utils import get_reg_32, set_reg_32, get_reg_64, set_reg_64


class Aarch64PtraceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an aarch64 process, specifically for the `ptrace` debugging backend."""

    def apply_on(self, target, target_class):
        target.regs = self.register_file

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target_class, "instruction_pointer"):
            return

        def get_property_64(name):
            def getter(self):
                return get_reg_64(self.regs, name)

            def setter(self, value):
                set_reg_64(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_32(name):
            def getter(self):
                return get_reg_32(self.regs, name)

            def setter(self, value):
                set_reg_32(self.regs, name, value)

            return property(getter, setter, None, name)

        for i in range(31):
            setattr(target_class, f"x{i}", get_property_64(f"x{i}"))
            setattr(target_class, f"w{i}", get_property_32(f"x{i}"))

        # setup special registers
        setattr(target_class, "pc", get_property_64("pc"))

        # setup generic "instruction_pointer" property
        setattr(target_class, "instruction_pointer", get_property_64("pc"))

        # setup generic syscall properties
        setattr(target_class, "syscall_number", get_property_64("x8"))
        setattr(target_class, "syscall_return", get_property_64("x0"))
        setattr(target_class, "syscall_arg0", get_property_64("x0"))
        setattr(target_class, "syscall_arg1", get_property_64("x1"))
        setattr(target_class, "syscall_arg2", get_property_64("x2"))
        setattr(target_class, "syscall_arg3", get_property_64("x3"))
        setattr(target_class, "syscall_arg4", get_property_64("x4"))
        setattr(target_class, "syscall_arg5", get_property_64("x5"))
