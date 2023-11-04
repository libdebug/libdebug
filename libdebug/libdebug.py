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

from libdebug.data.breakpoint import Breakpoint
from libdebug.interfaces.interface_helper import instantiate_preferred_interface
from typing import Callable, Self


class Debugger:
    """The Debugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    def __init__(self, argv):
        """Do not use this constructor directly.
        Use the `debugger` function instead.
        """
        self.argv = argv

        # running is True if and only if the process is currently running
        self.running = False

        # instanced is True if and only if the process has been started and has not been killed yet
        self.instanced = False

    def __del__(self):
        self.kill()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.kill()
        return False

    def start(self):
        """Starts the process. This method must be called before any other method, and any time the process needs to be restarted."""
        if self.instanced:
            self.kill()
        self.interface = instantiate_preferred_interface(self.argv)
        self.interface.run(self.argv)
        self.instanced = True

    def kill(self):
        """Kills the process."""
        self.interface.shutdown()
        self.instanced = False

    def cont(self):
        """Continues the execution of the process."""
        pass

    def block(self):
        """Stops the execution of the process."""
        pass

    def step(self):
        """Executes a single instruction before stopping again."""
        pass

    def b(
        self,
        location: int | bytes,
        callback: None | Callable[[Self, Breakpoint], None] = None,
    ):
        """Sets a breakpoint at the specified location. The callback will be executed when the breakpoint is hit.

        Args:
            location (int | bytes): The location of the breakpoint.
            callback (None | callable, optional): The callback to call when the breakpoint is hit. Defaults to None.
        """
        pass

    def jump(self, location: int | bytes):
        """Jumps to the specified location.

        Args:
            location (int | bytes): The location to jump to.
        """
        pass


def debugger(argv: str | list[str]) -> Debugger:
    """This function is used to create a new `Debugger` object. It takes as input the location of the binary to debug and returns a `Debugger` object.

    Args:
        argv (str | list[str]): The location of the binary to debug, and any additional arguments to pass to it.

    Returns:
        Debugger: The `Debugger` object.
    """

    return Debugger(argv)
