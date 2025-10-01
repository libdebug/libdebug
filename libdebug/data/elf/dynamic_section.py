#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DynamicSection:
    """Represents a dynamic section in an ELF file."""

    tag: int
    """The tag of the dynamic section."""
    value: int | str
    """The value of the dynamic section."""
    is_value_address: bool
    """Whether the value is an address."""
    reference_file: str
    """The path to the ELF file containing this section."""

    def __repr__(self: DynamicSection) -> str:
        """Return a developer-oriented string representation of the DynamicSection."""
        value_repr = hex(self.value) if self.is_value_address else repr(self.value)
        return f'DynamicSection(tag="{self.tag}", value={value_repr}, is_value_address={self.is_value_address}, reference_file="{self.reference_file}")'
