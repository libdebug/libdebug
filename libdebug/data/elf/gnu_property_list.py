#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.elf.gnu_property import GNUProperty


class GNUPropertyList(list[GNUProperty]):
    """A list of GNU properties in an ELF."""

    def __init__(self: GNUPropertyList, properties: list[GNUPropertyList]) -> None:
        """Initializes the GNUProperty list."""
        super().__init__(properties)

    def _search_by_type(self: GNUPropertyList, pr_type: str) -> GNUPropertyList:
        """Searches for a GNU property by type.

        Args:
            pr_type (str): The type mnemonic of the GNU property to search for.

        Returns:
            GNUPropertyList: The list of GNU properties that match the specified type.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the sections that exactly match the tag
        for property_entry in self:
            if property_entry.pr_type == pr_type:
                exact_match.append(property_entry)
            elif pr_type in property_entry.pr_type:
                no_exact_match.append(property_entry)
        return exact_match + no_exact_match

    def filter(self: GNUPropertyList, pr_type: str) -> GNUPropertyList:
        """Filters the GNU properties according to the specified pr_type.

        Args:
            pr_type (str): The pr_type of the GNU property to find.

        Returns:
            GNUPropertyList: The GNU properties matching the specified pr_type.
        """
        if isinstance(pr_type, str):
            filtered_properties = self._search_by_type(pr_type)
        else:
            raise TypeError("The value must be a string.")

        return GNUPropertyList(filtered_properties)

    def __hash__(self) -> int:
        """Return the hash of the GNU Properties list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the GNU Properties list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: GNUPropertyList) -> str:
        """Returns the string representation of the GNUPropertyList without the default factory."""
        return f"SectionList({super().__repr__()})"
