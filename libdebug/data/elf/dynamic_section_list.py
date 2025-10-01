#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.elf.dynamic_section import DynamicSection


class DynamicSectionList(list[DynamicSection]):
    """A list of dynamic sections in an ELF."""

    def __init__(self: DynamicSectionList, sections: list[DynamicSection]) -> None:
        """Initializes the DynamicSection list."""
        super().__init__(sections)

    def _search_by_tag(self: DynamicSection, tag: str) -> DynamicSectionList:
        """Searches for a dynamic section by tag.

        Args:
            tag (str): The tag of the dynamic section to search for.

        Returns:
            DynamicSectionList: The list of sections that match the specified tag.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the sections that exactly match the tag
        for dyn_section in self:
            if dyn_section.tag == tag:
                exact_match.append(dyn_section)
            elif tag in dyn_section.tag:
                no_exact_match.append(dyn_section)
        return exact_match + no_exact_match

    def filter(self: DynamicSectionList, tag: str) -> DynamicSectionList:
        """Filters the dynamic sections according to the specified tag.

        Args:
            tag (str): The tag of the dynamic section to find.

        Returns:
            DynamicSectionList: The dynamic sections matching the specified tag.
        """
        if isinstance(tag, str):
            filtered_dyn_sections = self._search_by_tag(tag)
        else:
            raise TypeError("The value must be a string.")

        return DynamicSectionList(filtered_dyn_sections)

    def __hash__(self) -> int:
        """Return the hash of the dynamic section list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the dynamic section list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: DynamicSectionList) -> str:
        """Returns the string representation of the DynamicSection without the default factory."""
        return f"SectionList({super().__repr__()})"
