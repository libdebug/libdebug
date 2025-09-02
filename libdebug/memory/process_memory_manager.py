#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from io import FileIO


class ProcessMemoryManager:
    """A class that provides accessors to the memory of a process, through /proc/pid/mem."""

    max_size = sys.maxsize

    def open(self: ProcessMemoryManager, process_id: int) -> None:
        """Initializes the ProcessMemoryManager."""
        self.process_id = process_id
        self._mem_file = None

    def _open(self: ProcessMemoryManager) -> None:
        self._mem_file = open(f"/proc/{self.process_id}/mem", "r+b", buffering=0)

    def _split_seek(self: ProcessMemoryManager, file_obj: FileIO, address: int) -> None:
        """Seeks to an address in a file, splitting the seek if necessary to avoid overflow."""
        if address > self.max_size:
            # We need to split the seek
            file_obj.seek(self.max_size, os.SEEK_SET)
            try:
                file_obj.seek(address - self.max_size, os.SEEK_CUR)
            except OverflowError as e:
                # The address must have been larger than 2 * max_size
                # This implies that it is invalid for the current architecture
                raise OSError(f"Address {address:#x} is not valid for this architecture") from e
        else:
            # We can seek directly
            file_obj.seek(address, os.SEEK_SET)

    def read(self: ProcessMemoryManager, address: int, size: int) -> bytes:
        """Reads memory from the target process.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """
        if not self._mem_file:
            self._open()

        self._split_seek(self._mem_file, address)
        return self._mem_file.read(size)

    def write(self: ProcessMemoryManager, address: int, data: bytes) -> None:
        """Writes memory to the target process.

        Args:
            address (int): The address to write to.
            data (bytes): The data to write.
        """
        if not self._mem_file:
            self._open()

        self._split_seek(self._mem_file, address)
        self._mem_file.write(data)

    def close(self: ProcessMemoryManager) -> None:
        """Closes the memory file."""
        if self._mem_file:
            self._mem_file.close()
            self._mem_file = None

    def is_available(self: ProcessMemoryManager) -> bool:
        """Checks if the process memory manager is available.

        Accessing memory through /proc/pid/mem requires ProcFS to be mounted as R/W,
        and for the debugged process to have the necessary permissions.

        Returns:
            bool: True if available, False otherwise.
        """
        return Path(f"/proc/{self.process_id}/mem").exists() and os.access(
            f"/proc/{self.process_id}/mem",
            os.R_OK | os.W_OK,
        )
