#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class ELFSection:
    """An ELF section of a binary object."""

    def __init__(self: ELFSection, name: str, address: int, size: int, offset: int) -> None:
        """
        Initialize an ELFSection instance with the given name, address, size and offset.

        Args:
            name (str): The name of the ELF section.
            address (int): The address of the ELF section.
            size (int): The size of the ELF section.
            offset (int): The offset of the ELF section.
        """
        self.name = name
        self.address = address
        self.size = size
        self.offset = offset
