#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from collections.abc import MutableSequence
from typing import Callable

from libdebug.liblog import liblog
from libdebug.state.debugging_context import DebuggingContext, debugging_context


class MemoryView(MutableSequence):
    """A memory interface for the target process.
    This class must be used to read and write memory of the target process.

    Attributes:
            getter (Callable[[int], bytes]): A function that reads memory from the target process.
            setter (Callable[[int, bytes], None]): A function that writes memory to the target process.
            maps_provider (Callable[[], list[MemoryMap]]): A function that returns the memory maps of the target process.
            unit_size (int, optional): The data size used by the getter and setter functions. Defaults to 8.
            align_to (int, optional): The address alignment that must be used when reading and writing memory. Defaults to 1.
    """

    context: DebuggingContext
    """The debugging context of the target process."""

    def __init__(
        self,
        getter: Callable[[int], bytes],
        setter: Callable[[int, bytes], None],
        unit_size: int = 8,
        align_to: int = 1,
    ):
        self.getter = getter
        self.setter = setter
        self.unit_size = unit_size
        self.align_to = align_to

        self.context = debugging_context()
        self.maps_provider = self.context.debugging_interface.maps

    def read(self, address: int, size: int) -> bytes:
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
                address + prefix_size, address + size - remainder, self.unit_size
            ):
                data += self.getter(i)

            if remainder:
                data += self.getter(address + size - remainder)[:remainder]

            return data

    def write(self, address: int, data: bytes):
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

    def __getitem__(self, key) -> bytes:
        if isinstance(key, int):
            address = self.context.resolve_address(key)

            return self.read(address, 1)
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.context.resolve_symbol(key.start)
            else:
                start = self.context.resolve_address(key.start)

            if isinstance(key.stop, str):
                stop = self.context.resolve_symbol(key.stop)
            else:
                stop = self.context.resolve_address(key.stop)

            if stop < start:
                raise ValueError("Invalid slice range")

            return self.read(start, stop - start)
        elif isinstance(key, str):
            address = self.context.resolve_symbol(key)

            return self.read(address, 1)
        elif isinstance(key, tuple):
            address, size = key

            if not isinstance(size, int):
                raise TypeError("Invalid size type")

            if isinstance(address, str):
                address = self.context.resolve_symbol(address)
            else:
                address = self.context.resolve_address(address)

            return self.read(address, size)
        else:
            raise TypeError("Invalid key type")

    def __setitem__(self, key, value):
        if isinstance(key, int):
            address = self.context.resolve_address(key)

            self.write(address, value)
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.context.resolve_symbol(key.start)
            else:
                start = self.context.resolve_address(key.start)

            if key.stop is not None:
                if isinstance(key.stop, str):
                    stop = self.context.resolve_symbol(key.stop)
                else:
                    stop = self.context.resolve_address(key.stop)

                if stop < start:
                    raise ValueError("Invalid slice range")

                if len(value) != stop - start:
                    liblog.warning(
                        "Mismatch between slice width and value size, writing {} bytes.".format(
                            len(value)
                        )
                    )

            self.write(start, value)
        elif isinstance(key, str):
            address = self.context.resolve_symbol(key)

            self.write(address, value)
        elif isinstance(key, tuple):
            address, size = key

            if not isinstance(size, int):
                raise TypeError("Invalid size type")

            if isinstance(address, str):
                address = self.context.resolve_symbol(address)
            else:
                address = self.context.resolve_address(address)

            if len(value) != size:
                liblog.warning(
                    "Mismatch between specified size and actual value size, writing {} bytes.".format(
                        len(value)
                    )
                )

            self.write(address, value)
        else:
            raise TypeError("Invalid key type")

    def __delitem__(self, key):
        raise NotImplementedError("MemoryView doesn't support deletion")

    def __len__(self):
        raise NotImplementedError("MemoryView doesn't support length")

    def insert(self, index, value):
        raise NotImplementedError("MemoryView doesn't support insertion")
