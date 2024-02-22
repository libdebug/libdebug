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

from typing import Callable

from libdebug.data.breakpoint import Breakpoint
from libdebug.state.thread_context import ThreadContext


class PtraceHardwareBreakpointManager:
    """An architecture-independent interface for managing hardware breakpoints.

    Attributes:
        thread (ThreadContext): The target thread.
        peek_user (callable): A function that reads a number of bytes from the target thread registers.
        poke_user (callable): A function that writes a number of bytes to the target thread registers.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(
        self,
        thread: ThreadContext,
        peek_user: Callable[[int, int], int],
        poke_user: Callable[[int, int, int], None],
    ):
        self.thread = thread
        self.peek_user = peek_user
        self.poke_user = poke_user
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
