#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryMap:
    """A memory map of the target process.

    Attributes:
        start (int): The start address of the memory map.
        end (int): The end address of the memory map.
        permissions (str): The permissions of the memory map.
        size (int): The size of the memory map.
        offset (int): The relative offset of the memory map.
        backing_file (str): The backing file of the memory map, or the symbolic name of the memory map.
    """

    start: int = 0
    end: int = 0
    permissions: str = ""
    size: int = 0

    offset: int = 0
    """The relative offset of the memory map inside the backing file, if any."""

    backing_file: str = ""
    """The backing file of the memory map, such as 'libc.so.6', or the symbolic name of the memory map, such as '[stack]'."""

    @staticmethod
    def parse(map: str) -> "MemoryMap":
        """Parses a memory map from a /proc/pid/maps string representation.

        Args:
            map (str): The string containing the memory map.

        Returns:
            MemoryMap: The parsed memory map.
        """
        try:
            address, permissions, offset, *_, backing_file = map.split(" ", 6)
            start = int(address.split("-")[0], 16)
            end = int(address.split("-")[1], 16)
            size = end - start
            offset = int(offset, 16)
            backing_file = backing_file.strip()
        except ValueError:
            raise ValueError(
                f"Invalid memory map: {map}. Please specify a valid memory map."
            )

        return MemoryMap(start, end, permissions, size, offset, backing_file)

    def __repr__(self) -> str:
        return f"MemoryMap(start={hex(self.start)}, end={hex(self.end)}, permissions={self.permissions}, size={hex(self.size)}, offset={hex(self.offset)}, backing_file={self.backing_file})"
