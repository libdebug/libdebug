#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.register_diff import RegisterDiff


class RegisterDiffAccessor:
    """Class used to access RegisterDiff objects for a thread snaphot."""

    def __repr__(self: RegisterDiffAccessor) -> str:
        """Return a string representation of the RegisterDiffAccessor object."""
        str_repr = "RegisterDiffAccessor("

        str_repr += "\n     old    new\n"

        # Get all registers
        actual_regs = dir(self)
        actual_regs = [reg for reg in actual_regs if not reg.startswith("_")]
        actual_regs.remove("filter")

        # Log all changes
        for attr_name in actual_regs:
            attr = self.__getattribute__(attr_name)

            if isinstance(attr, RegisterDiff) and attr.has_changed:
                if isinstance(attr.old_value, int):
                    str_repr += f"{attr_name}   {hex(attr.old_value)}    {hex(attr.new_value)}\n"
                else:
                    str_repr += f"{attr_name}   {attr.old_value}    {attr.new_value}\n"

        str_repr += ")"

        return str_repr