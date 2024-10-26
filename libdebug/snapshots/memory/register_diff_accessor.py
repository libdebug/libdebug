#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.snapshots.register_diff import RegisterDiff


class RegisterDiffAccessor:
    """Class used to access RegisterDiff objects for a thread snapshot."""

    def __repr__(self: RegisterDiffAccessor) -> str:
        """Return a string representation of the RegisterDiffAccessor object."""
        str_repr = "RegisterDiffAccessor(\n\n"
        
        # Header with column alignment
        str_repr += "{:<15} {:<20} {:<20}\n".format("Register", "Old Value", "New Value")
        str_repr += "-" * 60 + "\n"

        # Get all registers
        actual_regs = [reg for reg in dir(self) if isinstance(self.__getattribute__(reg), RegisterDiff)]

        # Log all changes
        for attr_name in actual_regs:
            attr = self.__getattribute__(attr_name)

            if isinstance(attr, RegisterDiff) and attr.has_changed:
                if isinstance(attr.old_value, int):
                    # Format integer values in hexadecimal without zero-padding
                    old_value = f"0x{attr.old_value:x}".rjust(18)
                    new_value = f"0x{attr.new_value:x}".rjust(18)
                elif isinstance(attr.old_value, str) and len(attr.old_value) > 16:
                    # If the register value is a large string (e.g., for xmm registers), display in full width
                    old_value = attr.old_value
                    new_value = attr.new_value
                else:
                    # For smaller values or non-hex values
                    old_value = str(attr.old_value).rjust(18)
                    new_value = str(attr.new_value).rjust(18)

                # Align output for consistent spacing between old and new values
                str_repr += "{:<15} {:<20} {:<20}\n".format(attr_name, old_value, new_value)

        str_repr += ")"

        return str_repr
