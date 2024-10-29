#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class RegisterDiffAccessor:
    """Class used to access RegisterDiff objects for a thread snapshot."""

    def __init__(
        self: RegisterDiffAccessor,
        generic_regs: list[str],
        special_regs: list[str],
        vec_fp_regs: list[str],
    ) -> None:
        """Initializes the RegisterDiffAccessor object.

        Args:
            generic_regs (list[str]): The list of generic registers to include in the repr.
            special_regs (list[str]): The list of special registers to include in the repr.
            vec_fp_regs (list[str]): The list of vector and floating point registers to include in the repr.
        """
        self._generic_regs = generic_regs
        self._special_regs = special_regs
        self._vec_fp_regs = vec_fp_regs

    def __repr__(self: RegisterDiffAccessor) -> str:
        """Return a string representation of the RegisterDiffAccessor object."""
        str_repr = "RegisterDiffAccessor(\n\n"

        # Header with column alignment
        str_repr += "{:<15} {:<20} {:<20}\n".format("Register", "Old Value", "New Value")
        str_repr += "-" * 60 + "\n"

        # Log all integer changes
        for attr_name in self._generic_regs:
            attr = self.__getattribute__(attr_name)

            if attr.has_changed:
                # Format integer values in hexadecimal without zero-padding
                old_value = f"0x{attr.old_value:x}".rjust(16)
                new_value = f"0x{attr.new_value:x}".rjust(16)
                # Align output for consistent spacing between old and new values
                str_repr += f"{attr_name:<15} {old_value:<20} {new_value:<20}\n"

        str_repr += "[...]\n"
        str_repr += ")"

        return str_repr
