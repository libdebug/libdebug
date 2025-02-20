#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.elf_section import ELFSection


class ELFSectionList(list[ELFSection]):
    """A list of ELF sections for a binary object."""

    def __init__(self: ELFSectionList, sections: list[ELFSection] | None = None) -> None:
        """Initialize an ELFSectionList instance.

        Args:
            sections (list[ELFSection]): The list of ELF sections to initialize the ELFSectionList with. Defaults to None.
        """
        if sections is None:
            self._sections = []
        else:
            self._sections = sections

    def __getitem__(self: ELFSectionList, key: int | str | range) -> ELFSection:
        """Return the ELF section at the given index or with the given name or the sections in a certain index range.

        Args:
            key (int | str | range): The index or name or range of the ELF sections to return.

        Returns:
            ELFSection: The ELF section at the given index or with the given name.
        """
        if isinstance(key, int):
            if abs(key) > len(self._sections):
                raise IndexError("ELF section index out of range")
            return self._sections[key]
        elif isinstance(key, str):
            # Check for exact matches (also add a dot in front of the key if it doesn't start with a dot)
            # Because ELF sections are often prefixed with a dot
            possible_matches = [key] + (["." + key] if not key.startswith(".") else [])

            for section in self._sections:
                if section.name in possible_matches:
                    return section
            raise KeyError(f"ELF section with name '{key}' not found")
        elif isinstance(key, range):
            return self._sections[key.start : key.stop : key.step]
        else:
            raise TypeError("Key must be an integer, string, or range")

    def __setitem__(self: ELFSectionList, key: int, value: ELFSection) -> None:
        """Unsupported operation."""
        raise NotImplementedError("Setting ELF sections is not supported")

    def __delitem__(self: ELFSectionList, key: int) -> None:
        """Unsupported operation."""
        raise NotImplementedError("Deleting ELF sections is not supported")
