#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini
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

from libdebug.interfaces.ptrace_interface import PtraceInterface
from libdebug.state.process_context import ProcessContext
from libdebug.utils.process_utils import (
    get_open_fds,
    get_process_maps,
    guess_base_address,
)
import os
import signal


class PtraceProcessContext(ProcessContext):
    interface: PtraceInterface
    """The debugging interface object."""

    def interrupt(self):
        """Synchronously interrupts the process."""
        if self.running:
            os.kill(self.process_id, signal.SIGSTOP)
            self.running = False

    def fds(self):
        """Returns the file descriptors of the process."""
        return get_open_fds(self.process_id)

    def maps(self):
        """Returns the memory maps of the process."""
        return get_process_maps(self.process_id)

    def base_address(self):
        """Returns the base address of the process."""
        return guess_base_address(self.process_id)
