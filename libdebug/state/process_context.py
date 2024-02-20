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

from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.utils.debugging_utils import (
    normalize_and_validate_address,
    resolve_symbol_in_maps,
)
from libdebug.utils.elf_utils import is_pie


class ProcessContext:
    """
    This object represents a process. It holds information about the process' state, maps and descriptors.
    """

    process_id: int
    """The process' ID."""

    interface: DebuggingInterface
    """The debugging interface object."""

    argv: list
    """The process' argv."""

    running: bool
    """True if and only if the process is currently running."""

    dead: bool
    """True if and only if the process is dead."""

    def __init__(
        self, process_id: int, interface: DebuggingInterface, argv: list = None
    ):
        self.process_id = process_id
        self.interface = interface
        self.argv = argv
        self.running = False
        self.dead = False

    def set_running(self):
        """Sets the process as running."""
        self.running = True

    def set_stopped(self):
        """Sets the process as stopped."""
        self.running = False

    def set_dead(self):
        """Sets the process as dead."""
        self.dead = True

    def interrupt(self):
        """Synchronously interrupts the process."""
        raise NotImplementedError()

    def is_pie(self):
        """Returns whether the executable is PIE or not."""
        return is_pie(self.argv[0])

    def fds(self):
        """Returns the file descriptors of the process."""
        raise NotImplementedError()

    def maps(self):
        """Returns the memory maps of the process."""
        raise NotImplementedError()

    def base_address(self):
        """Returns the base address of the process."""
        raise NotImplementedError()

    def resolve_address(self, address: int) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.

        Returns:
            int: The normalized and validated address.
        """
        maps = self.maps()
        normalized_address = normalize_and_validate_address(address, maps)
        return normalized_address

    def resolve_symbol(self, symbol: str) -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.

        Returns:
            int: The address of the symbol.
        """
        maps = self.maps()
        address = resolve_symbol_in_maps(symbol, maps)
        normalized_address = normalize_and_validate_address(address, maps)
        return normalized_address
