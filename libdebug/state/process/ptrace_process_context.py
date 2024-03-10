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

import os
import signal

from libdebug.state.debugging_context import debugging_context
from libdebug.state.process_context import ProcessContext
from libdebug.utils.process_utils import get_open_fds


class PtraceProcessContext(ProcessContext):
    """The debugging interface object."""

    def interrupt(self):
        """Synchronously interrupts the process."""
        if debugging_context.running:
            os.kill(debugging_context.process_id, signal.SIGSTOP)
            debugging_context.set_stopped()

    def fds(self):
        """Returns the file descriptors of the process."""
        return get_open_fds(self.process_id)

