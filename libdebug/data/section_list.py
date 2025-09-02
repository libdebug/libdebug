#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.section import Section


class SectionList(list):
    """A list of sections in the target process."""

    def __init__(self: SectionList, sections: list[Section]) -> None:
        """Initializes the SectionDict."""
        super().__init__(sections)

    def _search_by_address(self: SectionList, address: int) -> list[Section]:
        """Searches for a section by relative address.

        Args:
            address (int): The relative address of the section to search for.

        Returns:
            list[Section]: The list of sections that match the specified relative address.
        """
        # Find the backing file that contains the address
        target = None

        for section in self:
            if section.start <= address < section.end:
                target = section
                break

        if target:
            return [
                section,
            ]
        else:
            raise ValueError(
                f"Address {address:#x} does not belong to any section. You must specify a relative address.",
            )

    def _search_by_name(self: SectionList, name: str) -> list[Section]:
        """Searches for a section by name.

        Args:
            name (str): The name of the section to search for.

        Returns:
            list[Section]: The list of sections that match the specified name.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the sections that exactly match the name
        for section in self:
            if section.name == name:
                exact_match.append(section)
            elif name in section.name:
                no_exact_match.append(section)
        return exact_match + no_exact_match

    def filter(self: SectionList, value: int | str) -> SectionList[Section]:
        """Filters the sections according to the specified value.

        If the value is an integer, it is treated as a relative address.
        If the value is a string, it is treated as a section name.

        Args:
            value (int | str): The relative address or name of the section to find.

        Returns:
            SectionList[Section]: The sections matching the specified value.
        """
        if isinstance(value, int):
            filtered_sections = self._search_by_address(value)
        elif isinstance(value, str):
            filtered_sections = self._search_by_name(value)
        else:
            raise TypeError("The value must be an integer or a string.")

        return SectionList(filtered_sections, self._maps_source)

    def __getitem__(self: SectionList, key: str | int) -> SectionList[Section] | Section:
        """Returns the section with the specified name.

        Args:
            key (str, int): The name of the section to return, or the index of the section in the list.

        Returns:
            Section | SectionList[Section]: The section at the specified index, or the SectionList of sections with the specified name.
        """
        if not isinstance(key, str):
            return super().__getitem__(key)

        sections = [section for section in self if section.name == key]
        if not sections:
            raise KeyError(f"Section '{key}' not found.")
        return SectionList(sections)

    def __hash__(self) -> int:
        """Return the hash of the section list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the section list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: SectionList) -> str:
        """Returns the string representation of the SectionDict without the default factory."""
        return f"SectionList({super().__repr__()})"
