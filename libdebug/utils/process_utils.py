#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
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

import functools
import os
from ctypes import CDLL, c_int, c_ulong

from libdebug.data.memory_map import MemoryMap


@functools.cache
def get_process_maps(process_id) -> list[str]:
    """Returns the memory maps of the specified process.

    Args:
        process_id (int): The PID of the process whose memory maps should be returned.

    Returns:
        list: A list of `MemoryMap` objects, each representing a memory map of the specified process.
    """
    with open(f"/proc/{process_id}/maps", "r") as maps_file:
        maps = maps_file.readlines()

    parsed_maps = [MemoryMap.parse(map) for map in maps]

    return parsed_maps


@functools.cache
def guess_base_address(process_id) -> int:
    """Returns the base address of the specified process.

    Args:
        process_id (int): The PID of the process whose base address should be returned.

    Returns:
        int: The base address of the specified process.
    """
    maps = get_process_maps(process_id)
    return int(maps[0].split("-")[0], 16)


@functools.cache
def get_open_fds(process_id) -> list[str]:
    """Returns the file descriptors of the specified process.

    Args:
        process_id (int): The PID of the process whose file descriptors should be returned.

    Returns:
        list: A list of `FileDescriptor` objects, each representing a file descriptor of the specified process.
    """
    fds = []
    for fd in os.listdir(f"/proc/{process_id}/fd"):
        fds.append(fd)
    return fds


def invalidate_process_cache():
    """Invalidates the cache of the functions in this module. Must be executed any time the process executes code."""
    get_process_maps.cache_clear()
    guess_base_address.cache_clear()
    get_open_fds.cache_clear()


def disable_self_aslr():
    """Disables ASLR for the current process."""
    libc = CDLL("libc.so.6")

    libc.personality.argtypes = [c_ulong]
    libc.personality.restype = c_int

    personality = libc.personality(0xFFFFFFFF)

    ADDR_NO_RANDOMIZE = 0x0040000

    if personality & ADDR_NO_RANDOMIZE == ADDR_NO_RANDOMIZE:
        return

    retval = libc.personality(personality | ADDR_NO_RANDOMIZE)

    if retval == -1:
        raise RuntimeError("Failed to disable ASLR.")
