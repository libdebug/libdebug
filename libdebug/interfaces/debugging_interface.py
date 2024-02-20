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

from libdebug.architectures.register_holder import RegisterHolder
from libdebug.data.memory_view import MemoryView
from libdebug.data.breakpoint import Breakpoint
from libdebug.utils.pipe_manager import PipeManager
from typing import Callable


class DebuggingInterface:
    """The interface used by `Debugger` to communicate with the available debugging backends, such as `ptrace` or `gdb`."""

    def __init__(
        self,
        _create_new_thread: Callable[[int], "ThreadContext"],
        _delete_thread: Callable[[int], None],
    ):
        self._create_new_thread = _create_new_thread
        self._delete_thread = _delete_thread

    def run(
        self, argv: str | list[str], enable_aslr: bool, env: dict[str, str] = None
    ) -> PipeManager:
        """Runs the specified process.

        Args:
            argv (str | list[str]): The command line to execute.
            enable_aslr (bool): Whether to enable ASLR or not.
            env (dict[str, str], optional): The environment variables to use. Defaults to None.
        """
        pass

    def kill(self):
        """Instantly terminates the process."""
        pass

    def cont(self):
        """Continues the execution of the process."""
        pass

    def wait(self):
        """Waits for the process to stop."""
        pass

    def step(self, thread_id: int):
        """Executes a single instruction of the specified thread.

        Args:
            thread_id (int): The thread to step.
        """
        pass

    def provide_memory_view(self) -> MemoryView:
        """Returns a memory view of the process."""
        pass

    def get_register_holder(self, thread_id: int) -> RegisterHolder:
        """Returns the current value of all the available registers for the specified thread.
        Note: the register holder should then be used to automatically setup getters and setters for each register.
        """
        pass

    def set_breakpoint(self, breakpoint: Breakpoint):
        """Sets a breakpoint at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to set.
        """
        pass

    def restore_breakpoint(self, breakpoint: Breakpoint):
        """Restores the original instruction flow at the specified address.

        Args:
            breakpoint (Breakpoint): The breakpoint to restore.
        """
        pass
