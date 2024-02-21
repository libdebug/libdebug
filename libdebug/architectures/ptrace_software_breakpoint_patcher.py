#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
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

from libdebug.utils.libcontext import libcontext


def install_software_breakpoint(code: int) -> int:
    """Patch the instruction to be executed by the CPU.

    Args:
        code (int): the instruction to be patched.

    Returns:
        int: the patched instruction.
    """

    match libcontext.arch:
        case "amd64":
            return (code & (2**56 - 1) << 8) | 0xCC
        case "x86":
            return (code & (2**56 - 1) << 8) | 0xCC


def software_breakpoint_byte_size() -> int:
    """Return the size of a software breakpoint instruction."""

    match libcontext.arch:
        case "amd64":
            return 1
        case "x86":
            return 1
