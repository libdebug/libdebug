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


class DirectMemoryView(AbstractMemoryView):
    """A memory interface for the target process, intended for direct memory access.

    Attributes:
        internal_debugger (InternalDebugger): The internal debugger instance.
        getter (Callable[[int, int], bytes]): A function that reads a variable amount of data from the target's memory.
        setter (Callable[[int, bytes], None]): A function that writes memory to the target process.
        align_to (int, optional): The address alignment that must be used when reading and writing memory. Defaults to 1.
    """

    def __init__(
        self: DirectMemoryView,
        internal_debugger: InternalDebugger,
        getter: Callable[[int, int], bytes],
        setter: Callable[[int, bytes], None],
        align_to: int = 1,
    ) -> None:
        """Initializes the MemoryView."""
        super().__init__(internal_debugger)
        self.getter = getter
        self.setter = setter
        self.align_to = align_to

    def read(self: DirectMemoryView, address: int, size: int) -> bytes:
        """Reads memory from the target process.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """
        if self.align_to == 1:
            return self.getter(address, size)
        else:
            prefix = address % self.align_to
            base_address = address - prefix
            new_size = size + prefix
            data = self.getter(base_address, new_size)
            return data[prefix : prefix + size]

    def write(self: DirectMemoryView, address: int, data: bytes) -> None:
        """Writes memory to the target process.

        Args:
            address (int): The address to write to.
            data (bytes): The data to write.
        """
        size = len(data)

        if self.align_to == 1:
            self.setter(address, data)
        else:
            prefix = address % self.align_to
            base_address = address - prefix
            new_size = size + prefix
            prefix_data = self.getter(base_address, new_size)
            new_data = prefix_data[:prefix] + data + prefix_data[prefix + size :]
            self.setter(base_address, new_data)

    @property
    def maps(self: DirectMemoryView) -> MemoryMapList:
        """Returns a list of memory maps in the target process.

        Returns:
            MemoryMapList: The memory maps.
        """
        return self._internal_debugger.maps

