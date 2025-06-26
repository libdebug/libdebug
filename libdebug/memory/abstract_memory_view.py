#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco, Mario Polino. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from collections.abc import MutableSequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.memory_map import MemoryMap
from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog
from libdebug.utils.platform_utils import get_platform_gp_register_size
from libdebug.utils.search_utils import find_all_overlapping_occurrences


class AbstractMemoryView(MutableSequence, ABC):
    """An abstract memory interface for the target process.

    An implementation of class must be used to read and write memory of the target process.
    """

    def __init__(self: AbstractMemoryView) -> None:
        """Initializes the MemoryView."""
        self._internal_debugger = provide_internal_debugger(self)

    @abstractmethod
    def read(self: AbstractMemoryView, address: int, size: int) -> bytes:
        """Reads memory from the target process.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """

    @abstractmethod
    def write(self: AbstractMemoryView, address: int, data: bytes) -> None:
        """Writes memory to the target process.

        Args:
            address (int): The address to write to.
            data (bytes): The data to write.
        """

    def find(
        self: AbstractMemoryView,
        value: bytes | str | int,
        file: str = "all",
        start: int | None = None,
        end: int | None = None,
    ) -> list[int]:
        """Searches for the given value in the specified memory maps of the process.

        The start and end addresses can be used to limit the search to a specific range.
        If not specified, the search will be performed on the whole memory map.

        Args:
            value (bytes | str | int): The value to search for.
            file (str): The backing file to search the value in. Defaults to "all", which means all memory.
            start (int | None): The start address of the search. Defaults to None.
            end (int | None): The end address of the search. Defaults to None.

        Returns:
            list[int]: A list of offset where the value was found.
        """
        if isinstance(value, str):
            value = value.encode()
        elif isinstance(value, int):
            value = value.to_bytes(1, sys.byteorder)

        occurrences = []
        if file == "all" and start is None and end is None:
            for vmap in self.maps:
                liblog.debugger(f"Searching in {vmap.backing_file}...")
                try:
                    memory_content = self.read(vmap.start, vmap.end - vmap.start)
                except (OSError, OverflowError, ValueError):
                    # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                    continue
                occurrences += find_all_overlapping_occurrences(value, memory_content, vmap.start)
        elif file == "all" and start is not None and end is None:
            for vmap in self.maps:
                if vmap.end > start:
                    liblog.debugger(f"Searching in {vmap.backing_file}...")
                    read_start = max(vmap.start, start)
                    try:
                        memory_content = self.read(read_start, vmap.end - read_start)
                    except (OSError, OverflowError, ValueError):
                        # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                        continue
                    occurrences += find_all_overlapping_occurrences(value, memory_content, read_start)
        elif file == "all" and start is None and end is not None:
            for vmap in self.maps:
                if vmap.start < end:
                    liblog.debugger(f"Searching in {vmap.backing_file}...")
                    read_end = min(vmap.end, end)
                    try:
                        memory_content = self.read(vmap.start, read_end - vmap.start)
                    except (OSError, OverflowError, ValueError):
                        # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                        continue
                    occurrences += find_all_overlapping_occurrences(value, memory_content, vmap.start)
        elif file == "all" and start is not None and end is not None:
            # Search in the specified range, hybrid mode
            start = self.resolve_address(start, "hybrid", True)
            end = self.resolve_address(end, "hybrid", True)
            liblog.debugger(f"Searching in the range {start:#x}-{end:#x}...")
            memory_content = self.read(start, end - start)
            occurrences = find_all_overlapping_occurrences(value, memory_content, start)
        else:
            maps = self.maps.filter(file)
            if not maps:
                raise ValueError("No memory map found for the specified backing file.")
            start = self.resolve_address(start, file, True) if start is not None else maps[0].start
            end = self.resolve_address(end, file, True) if end is not None else maps[-1].end - 1

            liblog.debugger(f"Searching in the range {start:#x}-{end:#x}...")
            memory_content = self.read(start, end - start)

            occurrences = find_all_overlapping_occurrences(value, memory_content, start)

        return occurrences

    def find_pointers(
        self: AbstractMemoryView,
        where: int | str = "*",
        target: int | str = "*",
        step: int = 1,
    ) -> list[tuple[int, int]]:
        """
        Find all pointers in the specified memory map that point to the target memory map.

        If the where parameter or the target parameter is a string, it is treated as a backing file. If it is an integer, the memory map containing the address will be used.

        If "*", "ALL", "all" or -1 is passed, all memory maps will be considered.

        Args:
            where (int | str): Identifier of the memory map where we want to search for references. Defaults to "*", which means all memory maps.
            target (int | str): Identifier of the memory map whose pointers we want to find. Defaults to "*", which means all memory maps.
            step (int): The interval step size while iterating over the memory buffer. Defaults to 1.

        Returns:
            list[tuple[int, int]]: A list of tuples containing the address where the pointer was found and the pointer itself.
        """
        # Filter memory maps that match the target
        if target in {"*", "ALL", "all", -1}:
            target_maps = self._internal_debugger.maps
        else:
            target_maps = self._internal_debugger.maps.filter(target)

        if not target_maps:
            raise ValueError("No memory map found for the specified target.")

        target_backing_files = {vmap.backing_file for vmap in target_maps}

        # Filter memory maps that match the where parameter
        if where in {"*", "ALL", "all", -1}:
            where_maps = self._internal_debugger.maps
        else:
            where_maps = self._internal_debugger.maps.filter(where)

        if not where_maps:
            raise ValueError("No memory map found for the specified where parameter.")

        where_backing_files = {vmap.backing_file for vmap in where_maps}

        if len(where_backing_files) == 1 and len(target_backing_files) == 1:
            return self.__internal_find_pointers(where_maps, target_maps, step)
        elif len(where_backing_files) == 1:
            found_pointers = []
            for target_backing_file in target_backing_files:
                found_pointers += self.__internal_find_pointers(
                    where_maps,
                    self._internal_debugger.maps.filter(target_backing_file),
                    step,
                )
            return found_pointers
        elif len(target_backing_files) == 1:
            found_pointers = []
            for where_backing_file in where_backing_files:
                found_pointers += self.__internal_find_pointers(
                    self._internal_debugger.maps.filter(where_backing_file),
                    target_maps,
                    step,
                )
            return found_pointers
        else:
            found_pointers = []
            for where_backing_file in where_backing_files:
                for target_backing_file in target_backing_files:
                    found_pointers += self.__internal_find_pointers(
                        self._internal_debugger.maps.filter(where_backing_file),
                        self._internal_debugger.maps.filter(target_backing_file),
                        step,
                    )

        return found_pointers

    def __internal_find_pointers(
        self: AbstractMemoryView,
        where_maps: list[MemoryMap],
        target_maps: list[MemoryMap],
        stride: int,
    ) -> list[tuple[int, int]]:
        """Find all pointers to a specific memory map within another memory map. Internal implementation.

        Args:
            where_maps (list[MemoryMap]): The memory maps where to search for pointers.
            target_maps (list[MemoryMap]): The memory maps for which to search for pointers.
            stride (int): The interval step size while iterating over the memory buffer.

        Returns:
            list[tuple[int, int]]: A list of tuples containing the address where the pointer was found and the pointer itself.
        """
        found_pointers = []

        # Obtain the start/end of the target memory segment
        target_start_address = target_maps[0].start
        target_end_address = target_maps[-1].end

        # Obtain the start/end of the where memory segment
        where_start_address = where_maps[0].start
        where_end_address = where_maps[-1].end

        # Read the memory from the where memory segment
        if not self._internal_debugger.fast_memory:
            liblog.warning(
                "Fast memory reading is disabled. Using find_pointers with fast_memory=False may be very slow.",
            )
        try:
            where_memory_buffer = self.read(where_start_address, where_end_address - where_start_address)
        except (OSError, OverflowError):
            liblog.error(f"Cannot read the target memory segment with backing file: {where_maps[0].backing_file}.")
            return found_pointers

        # Get the size of a pointer in the target process
        pointer_size = get_platform_gp_register_size(self._internal_debugger.arch)

        # Get the byteorder of the target machine (endianness)
        byteorder = sys.byteorder

        # Search for references in the where memory segment
        append = found_pointers.append
        for i in range(0, len(where_memory_buffer), stride):
            reference = where_memory_buffer[i : i + pointer_size]
            reference = int.from_bytes(reference, byteorder=byteorder)
            if target_start_address <= reference < target_end_address:
                append((where_start_address + i, reference))

        return found_pointers

    def telescope(  # noqa: C901
        self: AbstractMemoryView,
        address: int,
        depth: int = 10,
        min_str_len: int = 3,
        max_str_len: int = 0x100,
    ) -> list[int | bytes]:
        """Returns a telescope of the memory at the specified address.

        Args:
            address (int): The address to telescope.
            depth (int, optional): The depth of the telescope. Defaults to 10.
            min_str_len (int, optional): The minimum length of a string to be resolved, if the found element is not a valid address. If -1, the element will never be resolved as a string. Defaults to 3.
            max_str_len (int, optional): The maximum length of a string to be resolved, if the found element is not a valid address. Defaults to 0x100.

        Returns:
            list[int | bytes]: The telescope chain. The last element might be both an integer or a bytestring, depending on the arguments provided and the content of the memory. The first element is always the address provided as argument.
        """
        if min_str_len < -1:
            raise ValueError("min_str_len must be -1 or greater.")

        if max_str_len < 1:
            raise ValueError("max_str_len must be greater than 0.")

        if depth < 1:
            raise ValueError("depth must be greater than 0.")

        if min_str_len > max_str_len:
            raise ValueError("min_str_len must be less than or equal to max_str_len.")

        addr_size = get_platform_gp_register_size(self._internal_debugger.arch)

        # Validate the address
        addr = self._internal_debugger.resolve_address(address, "absolute")

        chain: list[int | str] = [addr]
        for _ in range(depth):
            try:
                val = self.read(addr, addr_size)
                addr = int.from_bytes(val, sys.byteorder)
                chain.append(addr)
            except (OSError, OverflowError):
                break

        # The val variable contains the last read value, which can be a string or whatever
        lp = 0x20
        hp = 0x7E
        last_ptr = chain[-2]

        actual_val = None

        if min_str_len != -1 and len(val) < min_str_len:
            if not self._internal_debugger.fast_memory:
                liblog.warning(
                    "Fast memory reading is disabled. Using telescope with fast_memory=False may be slow.",
                )
            val = self.read(last_ptr, max_str_len)
            if all(b >= lp and b <= hp for b in val[:max_str_len]):
                null_byte = val.find(b"\x00")
                if null_byte != -1:
                    val = val[:null_byte]
                actual_val = val.decode("utf-8", errors="backslashreplace")
        elif min_str_len != -1 and all(b >= lp and b <= hp for b in val[:min_str_len]):
            if not self._internal_debugger.fast_memory:
                liblog.warning(
                    "Fast memory reading is disabled. Using telescope with fast_memory=False may be slow.",
                )
            val = self.read(last_ptr, max_str_len)
            null_byte = val.find(b"\x00")
            if null_byte != -1:
                val = val[:null_byte]
            actual_val = val.decode("utf-8", errors="backslashreplace")

        if actual_val is None:
            # The value was not a string matching the criteria, so we convert it to an integer
            val = int.from_bytes(val, sys.byteorder)

        chain[-1] = val

        return chain

    def __getitem__(self: AbstractMemoryView, key: int | slice | str | tuple) -> bytes:
        """Read from memory, either a single byte or a byte string.

        Args:
            key (int | slice | str | tuple): The key to read from memory.
        """
        return self._manage_memory_read_type(key)

    def __setitem__(self: AbstractMemoryView, key: int | slice | str | tuple, value: bytes) -> None:
        """Write to memory, either a single byte or a byte string.

        Args:
            key (int | slice | str | tuple): The key to write to memory.
            value (bytes): The value to write.
        """
        if not isinstance(value, bytes):
            raise TypeError("Invalid type for the value to write to memory. Expected bytes.")
        self._manage_memory_write_type(key, value)

    def _manage_memory_read_type(
        self: AbstractMemoryView,
        key: int | slice | str | tuple,
        file: str = "hybrid",
    ) -> bytes:
        """Manage the read from memory, according to the typing.

        Args:
            key (int | slice | str | tuple): The key to read from memory.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(key, int):
            address = self.resolve_address(key, file, skip_absolute_address_validation=True)
            try:
                return self.read(address, 1)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.resolve_symbol(key.start, file)
            else:
                start = self.resolve_address(key.start, file, skip_absolute_address_validation=True)

            if isinstance(key.stop, str):
                stop = self.resolve_symbol(key.stop, file)
            else:
                stop = self.resolve_address(key.stop, file, skip_absolute_address_validation=True)

            if stop < start:
                raise ValueError("Invalid slice range.")

            try:
                return self.read(start, stop - start)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, str):
            address = self.resolve_symbol(key, file)

            return self.read(address, 1)
        elif isinstance(key, tuple):
            return self._manage_memory_read_tuple(key)
        else:
            raise TypeError("Invalid key type.")

    def _manage_memory_read_tuple(self: AbstractMemoryView, key: tuple) -> bytes:
        """Manage the read from memory, when the access is through a tuple.

        Args:
            key (tuple): The key to read from memory.
        """
        if len(key) == 3:
            # It can only be a tuple of the type (address, size, file)
            address, size, file = key
            if not isinstance(file, str):
                raise TypeError("Invalid type for the backing file. Expected string.")
        elif len(key) == 2:
            left, right = key
            if isinstance(right, str):
                # The right element can only be the backing file
                return self._manage_memory_read_type(left, right)
            elif isinstance(right, int):
                # The right element must be the size
                address = left
                size = right
                file = "hybrid"
            else:
                raise TypeError("Invalid type for the size. Expected int or string.")
        else:
            raise TypeError("Tuple must have 2 or 3 elements.")

        if not isinstance(size, int):
            raise TypeError("Invalid type for the size. Expected int.")

        if isinstance(address, str):
            address = self.resolve_symbol(address, file)
        elif isinstance(address, int):
            address = self.resolve_address(address, file, skip_absolute_address_validation=True)
        else:
            raise TypeError("Invalid type for the address. Expected int or string.")

        try:
            return self.read(address, size)
        except OSError as e:
            raise ValueError("Invalid address.") from e

    def _manage_memory_write_type(
        self: AbstractMemoryView,
        key: int | slice | str | tuple,
        value: bytes,
        file: str = "hybrid",
    ) -> None:
        """Manage the write to memory, according to the typing.

        Args:
            key (int | slice | str | tuple): The key to read from memory.
            value (bytes): The value to write.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(key, int):
            address = self.resolve_address(key, file, skip_absolute_address_validation=True)
            try:
                self.write(address, value)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.resolve_symbol(key.start, file)
            else:
                start = self.resolve_address(key.start, file, skip_absolute_address_validation=True)

            if key.stop is not None:
                if isinstance(key.stop, str):
                    stop = self.resolve_symbol(key.stop, file)
                else:
                    stop = self.resolve_address(
                        key.stop,
                        file,
                        skip_absolute_address_validation=True,
                    )

                if stop < start:
                    raise ValueError("Invalid slice range")

                if len(value) != stop - start:
                    liblog.warning(f"Mismatch between slice width and value size, writing {len(value)} bytes.")

            try:
                self.write(start, value)
            except OSError as e:
                raise ValueError("Invalid address.") from e

        elif isinstance(key, str):
            address = self.resolve_symbol(key, file)

            self.write(address, value)
        elif isinstance(key, tuple):
            self._manage_memory_write_tuple(key, value)
        else:
            raise TypeError("Invalid key type.")

    def _manage_memory_write_tuple(self: AbstractMemoryView, key: tuple, value: bytes) -> None:
        """Manage the write to memory, when the access is through a tuple.

        Args:
            key (tuple): The key to read from memory.
            value (bytes): The value to write.
        """
        if len(key) == 3:
            # It can only be a tuple of the type (address, size, file)
            address, size, file = key
            if not isinstance(file, str):
                raise TypeError("Invalid type for the backing file. Expected string.")
        elif len(key) == 2:
            left, right = key
            if isinstance(right, str):
                # The right element can only be the backing file
                self._manage_memory_write_type(left, value, right)
                return
            elif isinstance(right, int):
                # The right element must be the size
                address = left
                size = right
                file = "hybrid"
            else:
                raise TypeError("Invalid type for the size. Expected int or string.")
        else:
            raise TypeError("Tuple must have 2 or 3 elements.")

        if not isinstance(size, int):
            raise TypeError("Invalid type for the size. Expected int.")

        if isinstance(address, str):
            address = self.resolve_symbol(address, file)
        elif isinstance(address, int):
            address = self.resolve_address(address, file, skip_absolute_address_validation=True)
        else:
            raise TypeError("Invalid type for the address. Expected int or string.")

        if len(value) != size:
            liblog.warning(f"Mismatch between specified size and actual value size, writing {len(value)} bytes.")

        try:
            self.write(address, value)
        except OSError as e:
            raise ValueError("Invalid address.") from e

    def __delitem__(self: AbstractMemoryView, key: int | slice | str | tuple) -> None:
        """MemoryView doesn't support deletion."""
        raise NotImplementedError("MemoryView doesn't support deletion")

    def __len__(self: AbstractMemoryView) -> None:
        """MemoryView doesn't support length."""
        raise NotImplementedError("MemoryView doesn't support length")

    def insert(self: AbstractMemoryView, index: int, value: int) -> None:
        """MemoryView doesn't support insertion."""
        raise NotImplementedError("MemoryView doesn't support insertion")

    @property
    def maps(self: AbstractMemoryView) -> list:
        """Returns the list of memory maps of the target process."""
        raise NotImplementedError("The maps property must be implemented in the subclass.")

    def resolve_address(
        self: AbstractMemoryView,
        address: int,
        backing_file: str,
        skip_absolute_address_validation: bool = False,
    ) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.
            backing_file (str): The backing file to resolve the address in.
            skip_absolute_address_validation (bool, optional): Whether to skip bounds checking for absolute addresses. Defaults to False.

        Returns:
            int: The normalized and validated address.

        Raises:
            ValueError: If the substring `backing_file` is present in multiple backing files.
        """
        return self._internal_debugger.resolve_address(
            address,
            backing_file,
            skip_absolute_address_validation,
        )

    def resolve_symbol(self: AbstractMemoryView, symbol: str, backing_file: str) -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.
            backing_file (str): The backing file to resolve the symbol in.

        Returns:
            int: The address of the symbol.
        """
        return self._internal_debugger.resolve_symbol(symbol, backing_file)
