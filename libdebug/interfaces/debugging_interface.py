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

from libdebug.architectures.register_holder import RegisterHolder


class DebuggingInterface:
    """The interface used by `Debugger` to communicate with the available debugging backends, such as `ptrace` or `gdb`."""

    def run(self, argv: str | list[str]):
        """Runs the specified process.

        Args:
            argv (str | list[str]): The command line to execute.
        """
        pass

    def attach(self, process_id: int):
        """Attaches to the specified process.

        Args:
            process_id (int): The PID of the process to attach to.
        """
        pass

    def shutdown(self):
        """Shuts down the debugging backend."""
        pass

    def wait_for_child(self) -> bool:
        """Waits for the child process to be ready for commands.

        Returns:
            bool: Whether the child process is still alive.
        """
        pass

    def fds(self):
        """Returns the file descriptors of the process."""
        pass

    def maps(self):
        """Returns the memory maps of the process."""
        pass

    def base_address(self):
        """Returns the base address of the process."""
        pass

    def is_pie(self):
        """Returns whether the executable is PIE or not."""
        pass

    def get_register_holder(self) -> RegisterHolder:
        """Returns the current value of all the available registers.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    def set_breakpoint(self, address: int, hardware_assisted: bool):
        """Sets a breakpoint at the specified address.

        Args:
            address (int): The address where the breakpoint should be set.
            hardware_assisted (bool): Whether the breakpoint should be hardware-assisted or purely software.
        """
        pass

    def restore_breakpoint(self, address: int, hardware: bool):
        """Restores the original instruction flow at the specified address.

        Args:
            address (int): The address at which the breakpoint was set.
            hardware (bool): Whether the breakpoint was hardware or software.
        """
        pass

    def ensure_stopped(self):
        """Ensures that the process is stopped."""
        pass

    def continue_execution(self):
        """Continues the execution of the process."""
        pass

    def step_execution(self):
        """Executes a single instruction before stopping again."""
        pass

    def resolve_address(self, address: int) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.

        Returns:
            int: The normalized and validated address.

        Throws:
            ValueError: If the address is not valid.
        """
        pass
