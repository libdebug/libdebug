#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class DynamicSection:
    """Represents a dynamic section in an ELF file."""

    def __init__(
        self: DynamicSection,
        tag: int,
        value: int | str,
        is_value_address: bool,
        reference_file: str,
    ) -> None:
        """Initializes the Section.

        Args:
            tag (int): The tag of the dynamic section.
            value (int | str): The value of the dynamic section.
            is_value_address (bool): Whether the value is an address.
            reference_file (str): The path to the ELF file containing this section.
        """
        self.tag = tag
        self.value = value
        self.is_value_address = is_value_address
        self.reference_file = reference_file

    def __repr__(self: DynamicSection) -> str:
        """Return a developer-oriented string representation of the DynamicSection."""
        return f'DynamicSection(tag={self.tag}, value={self.value}, is_value_address={self.is_value_address}, reference_file="{self.reference_file}")'
