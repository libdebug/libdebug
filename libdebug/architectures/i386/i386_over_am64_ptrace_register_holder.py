#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.register_holder import PtraceRegisterHolder
from libdebug.utils.register_utils import (
    get_reg_8h,
    get_reg_8l,
    get_reg_16,
    get_reg_32,
    set_reg_8h,
    set_reg_8l,
    set_reg_16,
    set_reg_32,
)

I386_GP_REGS = ["a", "b", "c", "d"]

I386_BASE_REGS = ["bp", "sp", "si", "di"]


class I386POverAmd64traceRegisterHolder(PtraceRegisterHolder):
    """A class that provides views and setters for the registers of an i386 process when debugger over an x86_64 system, specifically for the `ptrace` debugging backend."""

    def apply_on(self, target, target_class):
        target.regs = self.register_file

        # Do note that an i386 application running on an x86_64 system will have the same register file as an x86_64 application
        # Thus, the accessors must look for the x86_64 register names in the underlying file
        # This is of course not true if the application is running on a real i386 system

        # If the accessors are already defined, we don't need to redefine them
        if hasattr(target, "instruction_pointer"):
            return

        def get_property_32(name):
            def getter(self):
                return get_reg_32(self.regs, name)

            def setter(self, value):
                set_reg_32(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_16(name):
            def getter(self):
                return get_reg_16(self.regs, name)

            def setter(self, value):
                set_reg_16(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_8l(name):
            def getter(self):
                return get_reg_8l(self.regs, name)

            def setter(self, value):
                set_reg_8l(self.regs, name, value)

            return property(getter, setter, None, name)

        def get_property_8h(name):
            def getter(self):
                return get_reg_8h(self.regs, name)

            def setter(self, value):
                set_reg_8h(self.regs, name, value)

            return property(getter, setter, None, name)

        # setup accessors
        for name in I386_GP_REGS:
            name_64 = "r" + name + "x"
            name_32 = "e" + name + "x"
            name_16 = name + "x"
            name_8l = name + "l"
            name_8h = name + "h"

            setattr(target_class, name_32, get_property_32(name_64))
            setattr(target_class, name_16, get_property_16(name_64))
            setattr(target_class, name_8l, get_property_8l(name_64))
            setattr(target_class, name_8h, get_property_8h(name_64))

        for name in I386_BASE_REGS:
            name_64 = "r" + name
            name_32 = "e" + name
            name_16 = name

            setattr(target_class, name_32, get_property_32(name_64))
            setattr(target_class, name_16, get_property_16(name_64))

        # setup special registers
        setattr(target_class, "eip", get_property_32("rip"))

        # setup generic "instruction_pointer" property
        setattr(target_class, "instruction_pointer", get_property_32("rip"))
