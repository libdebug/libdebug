#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.memory.abstract_memory_view import AbstractMemoryView

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.debugger.internal_debugger import InternalDebugger


class ChunkedMemoryView(AbstractMemoryView):
    """A memory interface for the target process, intended for chunk-based memory access.

    Attributes:
        internal_debugger (InternalDebugger): The internal debugger instance.
        getter (Callable[[int], bytes]): A function that reads a chunk of memory from the target process.
        setter (Callable[[int, bytes], None]): A function that writes a chunk of memory to the target process.
        unit_size (int, optional): The chunk size used by the getter and setter functions. Defaults to 8.
        align_to (int, optional): The address alignment that must be used when reading and writing memory. Defaults to 1.
    """

    def __init__(
        self: ChunkedMemoryView,
        internal_debugger: InternalDebugger,
        getter: Callable[[int], bytes],
        setter: Callable[[int, bytes], None],
        unit_size: int = 8,
        align_to: int = 1,
    ) -> None:
        """Initializes the MemoryView."""
        super().__init__(internal_debugger)
        self.getter = getter
        self.setter = setter
        self.unit_size = unit_size
        self.align_to = align_to

    def read(self: ChunkedMemoryView, address: int, size: int) -> bytes:
        """Reads memory from the target process.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """
        if self.align_to == 1:
            data = b""

            remainder = size % self.unit_size

            for i in range(address, address + size - remainder, self.unit_size):
                data += self.getter(i)

            if remainder:
                data += self.getter(address + size - remainder)[:remainder]

            return data
        else:
            prefix = address % self.align_to
            prefix_size = self.unit_size - prefix

            data = self.getter(address - prefix)[prefix:]

            remainder = (size - prefix_size) % self.unit_size

            for i in range(
                address + prefix_size,
                address + size - remainder,
                self.unit_size,
            ):
                data += self.getter(i)

            if remainder:
                data += self.getter(address + size - remainder)[:remainder]

            return data

    def write(self: ChunkedMemoryView, address: int, data: bytes) -> None:
        """Writes memory to the target process.

        Args:
            address (int): The address to write to.
            data (bytes): The data to write.
        """
        size = len(data)

        if self.align_to == 1:
            remainder = size % self.unit_size
            base = address
        else:
            prefix = address % self.align_to
            prefix_size = self.unit_size - prefix

            prev_data = self.getter(address - prefix)

            self.setter(address - prefix, prev_data[:prefix_size] + data[:prefix])

            remainder = (size - prefix_size) % self.unit_size
            base = address + prefix_size

        for i in range(base, address + size - remainder, self.unit_size):
            self.setter(i, data[i - address : i - address + self.unit_size])

        if remainder:
            prev_data = self.getter(address + size - remainder)
            self.setter(
                address + size - remainder,
                data[size - remainder :] + prev_data[remainder:],
            )

    @property
    def maps(self: ChunkedMemoryView) -> MemoryMapList:
        """Returns a list of memory maps in the target process.

        Returns:
            MemoryMapList: The memory maps.
        """
        return self._internal_debugger.maps

