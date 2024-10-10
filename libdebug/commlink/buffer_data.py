#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class BufferData:
    """Class that represents a buffer to store data coming from stdout and stderr."""

    def __init__(self: BufferData, data: bytes) -> None:
        """Initializes the BufferData object."""
        self.data = data

    def clear(self: BufferData) -> None:
        """Clears the buffer."""
        self.data = b""

    def get_data(self: BufferData) -> bytes:
        """Returns the data stored in the buffer."""
        return self.data

    def append(self, data: bytes) -> None:
        """Appends data to the buffer."""
        self.data += data

    def overwrite(self, data: bytes) -> None:
        """Overwrites the buffer with the given data."""
        self.data = data

    def find(self: BufferData, pattern: bytes) -> int:
        """Finds the first occurrence of the given pattern in the buffer."""
        return self.data.find(pattern)

    def __len__(self: BufferData) -> int:
        """Returns the length of the buffer."""
        return len(self.data)

    def __repr__(self: BufferData) -> str:
        """Returns a string representation of the buffer."""
        return self.data.__repr__()

    def __getitem__(self: BufferData, key: int) -> bytes:
        """Returns the item at the given index."""
        return self.data[key]
