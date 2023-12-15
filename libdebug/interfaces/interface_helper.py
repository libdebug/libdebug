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

from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.interfaces.interfaces import AvailableInterfaces
from libdebug.interfaces.ptrace_interface import PtraceInterface


def debugging_interface_provider(
    interface: AvailableInterfaces = AvailableInterfaces.PTRACE
) -> DebuggingInterface:
    """Returns an instance of the debugging interface to be used by the `Debugger` class."""
    match interface:
        case AvailableInterfaces.PTRACE:
            return PtraceInterface()
        case _:
            raise NotImplementedError(f"Interface {interface} not available.")
