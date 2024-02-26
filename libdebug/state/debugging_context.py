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

from __future__ import annotations

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.utils.pipe_manager import PipeManager


class DebuggingContext:
    """
    A class that holds the global debugging state.
    """

    _instance = None

    aslr_enabled: bool
    """A flag that indicates if ASLR is enabled or not."""

    argv: list[str]
    """The command line arguments of the debugged process."""

    env: dict[str, str]
    """The environment variables of the debugged process."""

    _breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process.
    Key: the address of the breakpoint."""

    _threads: dict[int, "ThreadContext"]
    """A dictionary of all the threads of the process.
    Key: the thread ID."""

    pipe_manager: PipeManager
    """The pipe manager used to communicate with the debugged process."""

    _is_running: bool
    """The overall state of the debugged process. True if the process is running, False otherwise."""

    process_id: int
    """The PID of the debugged process."""

    debugging_interface: "DebuggingInterface"
    """The debugging interface used to communicate with the debugged process."""

    memory: MemoryView
    """The memory view of the debugged process."""

    _threaded_memory: MemoryView
    """The memory view of the debugged process, used for operations in the background thread."""

    def __new__(cls) -> DebuggingContext:
        """Create a new instance of the class if it does not exist yet.

        Returns:
            DebuggingContext: the instance of the class.
        """

        if cls._instance is None:
            cls._instance = super(DebuggingContext, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the context"""

        if self._initialized:
            return

        # These must be reinitialized on every call to "debugger"
        self.aslr_enabled = False
        self.argv = []
        self.env = {}
        self._breakpoints = {}
        self._threads = {}

        self.clear()

        self._initialized = True

    def clear(self):
        """Clear the context"""

        # These must be reinitialized on every call to "run"
        self._breakpoints.clear()
        self._threads.clear()
        self.pipe_manager = None
        self._is_running = False
        self.process_id = 0

    @property
    def breakpoints(self) -> dict[int, Breakpoint]:
        """Get the breakpoints dictionary.

        Returns:
            dict[int, Breakpoint]: the breakpoints dictionary.
        """

        return self._breakpoints

    def insert_new_breakpoint(self, breakpoint: Breakpoint):
        """Insert a new breakpoint in the context.

        Args:
            breakpoint (Breakpoint): the breakpoint to insert.
        """

        self._breakpoints[breakpoint.address] = breakpoint

    def remove_breakpoint(self, breakpoint: Breakpoint):
        """Remove a breakpoint from the context.

        Args:
            address (int): the address of the breakpoint to remove.
        """

        del self._breakpoints[breakpoint.address]

    @property
    def threads(self) -> dict[int, "ThreadContext"]:
        """Get the threads dictionary.

        Returns:
            dict[int, ThreadContext]: the threads dictionary.
        """

        return self._threads

    def insert_new_thread(self, thread: "ThreadContext"):
        """Insert a new thread in the context.

        Args:
            thread (ThreadContext): the thread to insert.
        """

        self._threads[thread.thread_id] = thread

    def remove_thread(self, thread_id: int):
        """Remove a thread from the context.

        Args:
            thread_id (int): the ID of the thread to remove.
        """

        del self._threads[thread_id]

    @property
    def running(self) -> bool:
        """Get the state of the process.

        Returns:
            bool: True if the process is running, False otherwise.
        """

        return self._is_running

    def set_running(self) -> bool:
        """Set the state of the process to running.

        Returns:
            bool: True if the process is running, False otherwise.
        """

        self._is_running = True

    def set_stopped(self) -> bool:
        """Set the state of the process to stopped.

        Returns:
            bool: True if the process is running, False otherwise.
        """

        self._is_running = False

    @property
    def dead(self) -> bool:
        """Get the state of the process.

        Returns:
            bool: True if the process is dead, False otherwise.
        """

        return not self._threads


debugging_context = DebuggingContext()
