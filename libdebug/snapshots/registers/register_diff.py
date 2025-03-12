#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RegisterDiff:
    """This object represents a diff between registers in a thread snapshot."""

    old_value: int | float
    """The old value of the register."""

    new_value: int | float
    """The new value of the register."""

    has_changed: bool
    """Whether the register has changed."""

    def __repr__(self: RegisterDiff) -> str:
        """Return a string representation of the RegisterDiff object."""
        old_value_str = hex(self.old_value) if isinstance(self.old_value, int) else str(self.old_value)
        new_value_str = hex(self.new_value) if isinstance(self.new_value, int) else str(self.new_value)
        return f"RegisterDiff(old_value={old_value_str}, new_value={new_value_str}, has_changed={self.has_changed})"
