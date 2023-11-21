#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
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

from libdebug.data.breakpoint import Breakpoint
from typing import Callable


class PtraceHardwareBreakpointManager:
    """An architecture-independent interface for managing hardware breakpoints.

    Attributes:
        peek_mem (callable): A function that reads a number of bytes from the target process memory.
        poke_mem (callable): A function that writes a number of bytes to the target process memory.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self, peek_mem: Callable[[int], int], poke_mem: Callable[[int, int], None]
    ):
        self.peek_mem = peek_mem
        self.poke_mem = poke_mem
        self.breakpoint_count = 0

    def install_breakpoint(bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        pass

    def remove_breakpoint(bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        pass

    def available_breakpoints() -> int:
        """Returns the number of available hardware breakpoint registers."""
        pass
