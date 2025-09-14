#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.dynamic_section import DynamicSection


class DynamicSectionList(list[DynamicSection]):
    """A list of dynamic sections in the target process."""

    def __init__(self: DynamicSectionList, sections: list[DynamicSection]) -> None:
        """Initializes the DynamicSection dict."""
        super().__init__(sections)

    def _search_by_tag(self: DynamicSection, name: str) -> list[DynamicSection]:
        """Searches for a dynamic section by name.

        Args:
            name (str): The tag of the dynamic section to search for.

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

    def filter(self: DynamicSectionList, tag: str) -> DynamicSectionList[DynamicSection]:
        """Filters the sections according to the specified tag.

        Args:
            tag (str): The tag of the dynamic section to find.

        Returns:
            SectionList[Section]: The sections matching the specified tag.
        """
        if isinstance(tag, str):
            filtered_sections = self._search_by_tag(tag)
        else:
            raise TypeError("The value must be an integer or a string.")

        return DynamicSectionList(filtered_sections)

    def __hash__(self) -> int:
        """Return the hash of the dynamic section list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the dynamic section list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: DynamicSectionList) -> str:
        """Returns the string representation of the DinamicSection without the default factory."""
        return f"SectionList({super().__repr__()})"
