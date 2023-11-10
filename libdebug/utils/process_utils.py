#
# This file is part of libdebug Python library (https://github.com/gabriele180698/libdebug).
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

import os

def get_process_maps(process_id):
    """Returns the memory maps of the specified process.

    Args:
        process_id (int): The PID of the process whose memory maps should be returned.

    Returns:
        list: A list of `MemoryMap` objects, each representing a memory map of the specified process.
    """
    with open(f"/proc/{process_id}/maps", "r") as maps_file:
        maps = maps_file.readlines()
    return maps

def guess_base_address(process_id):
    """Returns the base address of the specified process.

    Args:
        process_id (int): The PID of the process whose base address should be returned.

    Returns:
        int: The base address of the specified process.
    """
    maps = get_process_maps(process_id)
    return int(maps[0].split("-")[0], 16)

def get_open_fds(process_id):
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