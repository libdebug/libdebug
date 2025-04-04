#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Symbol:
    """A symbol in the target process.

    start (int): The start address of the symbol in the target process.
    end (int): The end address of the symbol in the target process.
    name (str): The name of the symbol in the target process.
    backing_file (str): The backing file of the symbol in the target process.
    reference_file (str): The file that the symbol's offsets refer to in the target process.
    reference_build_id (str): The build ID of the reference file.
    is_external (bool): Whether the symbol is external or not.
    """

    start: int
    end: int
    name: str
    backing_file: str
    reference_file: str
    reference_build_id: str
    is_external: bool

    def __hash__(self: Symbol) -> int:
        """Returns the hash of the symbol."""
        return hash((self.start, self.end, self.name, self.backing_file))

    def __repr__(self: Symbol) -> str:
        """Returns the string representation of the symbol."""
        return f"Symbol(start={self.start:#x}, end={self.end:#x}, name={self.name}, backing_file={self.backing_file}, reference_file={self.reference_file}, reference_build_id={self.reference_build_id}, is_external={self.is_external})"
