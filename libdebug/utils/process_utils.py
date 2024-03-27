#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import os

from libdebug.cffi._personality_cffi import lib as lib_personality
from libdebug.data.memory_map import MemoryMap


@functools.cache
def get_process_maps(process_id) -> list[MemoryMap]:
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
    get_open_fds.cache_clear()


def disable_self_aslr():
    """Disables ASLR for the current process."""
    retval = lib_personality.disable_aslr()

    if retval == -1:
        raise RuntimeError("Failed to disable ASLR.")
