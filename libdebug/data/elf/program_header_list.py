#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.elf.program_header import ProgramHeader


class ProgramHeaderList(list[ProgramHeader]):
    """A list of program headers in an ELF."""

    def _search_by_type(self: ProgramHeaderList, header_type: str) -> ProgramHeaderList:
        """Searches for a program header by type.

        Args:
            header_type (str): The type of the program header to search for.

        Returns:
            ProgramHeaderList: The list of program headers that match the specified name.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the type that exactly match the name
        for program_header in self:
            if program_header.header_type == header_type:
                exact_match.append(program_header)
            elif header_type in program_header.header_type:
                no_exact_match.append(program_header)
        return exact_match + no_exact_match

    def filter(self: ProgramHeaderList, header_type: str) -> ProgramHeaderList:
        """Filters the program headers according to the specified type.

        Args:
            header_type (str): The type of the program header to find.

        Returns:
            ProgramHeaderList: The program headers matching the specified type.
        """
        if isinstance(header_type, str):
            filtered_headers = self._search_by_type(header_type)
        else:
            raise TypeError("The value must be a string.")

        return ProgramHeaderList(filtered_headers)

    def __repr__(self: ProgramHeaderList) -> str:
        """Returns the string representation of the program header without the default factory."""
        return f"ProgramHeaderList({super().__repr__()})"
