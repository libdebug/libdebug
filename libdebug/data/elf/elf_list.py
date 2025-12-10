#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.elf.elf import ELF


class ELFList(list):
    """A list of elf files in the target process."""

    def __init__(self: ELFList, elfs: list[ELF]) -> None:
        """Initializes the ELFList."""
        super().__init__(elfs)

    def _search_by_name(self: ELFList, name: str) -> list[ELF]:
        """Searches for an ELF by partial or exact match of name or path.

        Args:
            name (str): The pattern to search for.

        Returns:
            list[ELF]: The list of elfs that match the specified name.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the elfs that exactly match the name
        for elf in self:
            curr_name = Path(elf.path).name

            if name in (curr_name, elf.path):
                exact_match.append(elf)
            elif name in elf.path:
                no_exact_match.append(elf)
        return exact_match + no_exact_match

    def filter(self: ELFList, value: str) -> ELFList:
        """Filters the elfs according to the specified value.

        Args:
            value (str): The name of the elf to find.

        Returns:
            ELFList[ELF]: The elfs matching the specified value.
        """
        if isinstance(value, str):
            filtered_elfs = self._search_by_name(value)
        else:
            raise TypeError("The value must be a string.")

        return ELFList(filtered_elfs)

    def __getitem__(self: ELFList, key: str | int) -> ELFList:
        """Returns the elf with exactly the specified name or at the specified index.

        Args:
            key (str, int): The exact name or path of the ELF or its index.

        Returns:
            ELFList[ELF]: List of elfs with the specified name.
        """
        if not isinstance(key, str):
            return super().__getitem__(key)

        elfs = [elf for elf in self if key in (Path(elf.path).name, elf.path)]

        if not elfs:
            raise KeyError(f"ELF '{key}' not found.")
        return ELFList(elfs)

    def __hash__(self) -> int:
        """Return the hash of the elf list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the elf list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: ELFList) -> str:
        """Returns the string representation of the ELFList without the default factory."""
        return f"ELFList({super().__repr__()})"
