#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini, Gabriele Digregorio.
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

import os
from queue import Queue
from threading import Thread
from typing import Callable

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.state.debugging_context import debugging_context
from libdebug.state.process.process_context_provider import provide_process_context
from libdebug.state.process_context import ProcessContext
from libdebug.state.thread_context import ThreadContext


class Debugger:
    """The Debugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    memory: MemoryView = None
    """The memory view of the process."""

    process_context: ProcessContext = None
    """The process context object."""

    breakpoints: dict[int, Breakpoint] = {}
    """A dictionary of all the breakpoints set on the process. The keys are the absolute addresses of the breakpoints."""

    threads: dict[int, ThreadContext] = {}
    """A dictionary of all the threads in the process. The keys are the thread IDs."""

    instanced: bool = False
    """Whether the process was started and has not been killed yet."""

    interface: DebuggingInterface = None
    """The debugging interface used to interact with the process."""

    _polling_thread: Thread = None
    """The background thread used to poll the process for state change."""

    _polling_thread_command_queue: Queue = None
    """The queue used to send commands to the background thread."""

    _polling_thread_response_queue: Queue = None
    """The queue used to receive responses from the background thread."""

    _threaded_memory: MemoryView = None
    """The memory view of the process, used for operations in the background thread."""

    def __init__(self):
        """Do not use this constructor directly.
        Use the `debugger` function instead.
        """
        # validate that the binary exists
        if not os.path.isfile(debugging_context.argv[0]):
            raise RuntimeError("The specified binary file does not exist.")

        self.interface = provide_debugging_interface()
        debugging_context.debugging_interface = self.interface

        self.process_context = provide_process_context()

        # threading utilities
        self._polling_thread_command_queue = Queue()
        self._polling_thread_response_queue = Queue()

        self.breakpoints = debugging_context.breakpoints
        self.threads = debugging_context.threads

        self._start_processing_thread()
        self._setup_memory_view()

    def run(self):
        """Starts the process and waits for it to stop."""
        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()

        self.instanced = True

        if not self._polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self._polling_thread_command_queue.put((self.__threaded_run, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        assert debugging_context.pipe_manager is not None

        return debugging_context.pipe_manager

    def attach(self, pid: int):
        """Attaches to an existing process."""
        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")

        self.instanced = True

        if not self._polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self._polling_thread_command_queue.put((self.__threaded_attach, (pid,)))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def _start_processing_thread(self):
        """Starts the thread that will poll the traced process for state change."""
        # Set as daemon so that the Python interpreter can exit even if the thread is still running
        self._polling_thread = Thread(
            target=self._polling_thread_function,
            name="libdebug_polling_thread",
            daemon=True,
        )
        self._polling_thread.start()

    def kill(self):
        """Kills the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot kill.")

        self._polling_thread_command_queue.put((self.__threaded_kill, ()))

        # If the process is running, interrupt it
        self.process_context.interrupt()

        self.memory = None
        self.instanced = None

        if debugging_context.pipe_manager is not None:
            debugging_context.pipe_manager.close()
            debugging_context.pipe_manager = None

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        debugging_context.clear()
        self.interface.reset()

    def cont(self):
        """Continues the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot continue.")

        if debugging_context.dead or debugging_context.running:
            raise RuntimeError("Process is dead or already running.")

        self._polling_thread_command_queue.put((self.__threaded_cont, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def wait(self):
        """Waits for the process to stop."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot wait.")

        if debugging_context.dead or not debugging_context.running:
            raise RuntimeError("Process is dead or not running.")

        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def step(self, thread: ThreadContext = None):
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext, optional): The thread to step. Defaults to None.
        """
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if thread is None:
            # If no thread is specified, we use the first thread
            thread = next(iter(self.threads.values()))

        self._polling_thread_command_queue.put((self.__threaded_step, (thread,)))
        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def step_until(
        self, position: int | str, thread: ThreadContext = None, max_steps: int = -1
    ):
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            thread (ThreadContext, optional): The thread to step. Defaults to None.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if thread is None:
            # If no thread is specified, we use the first thread
            thread = next(iter(self.threads.values()))

        if isinstance(position, str):
            address = self.process_context.resolve_symbol(position)
        else:
            address = self.process_context.resolve_address(position)

        arguments = (
            thread,
            address,
            max_steps,
        )

        self._polling_thread_command_queue.put((self.__threaded_step_until, arguments))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def breakpoint(
        self,
        position: int | str,
        hardware: bool = False,
        callback: None | Callable[[Debugger, Breakpoint], None] = None,
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
        """
        if not self.instanced:
            raise RuntimeError("Process not running, cannot set a breakpoint.")

        if debugging_context.running:
            raise RuntimeError("Cannot set a breakpoint while the process is running.")

        if isinstance(position, str):
            address = self.process_context.resolve_symbol(position)
        else:
            address = self.process_context.resolve_address(position)
            position = address

        bp = Breakpoint(address, position, 0, hardware, callback)

        self._polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        # the breakpoint should have been set by interface
        assert address in self.breakpoints and self.breakpoints[address] is bp

        return bp

    def __getattr__(self, name: str) -> object:
        """This function is called when an attribute is not found in the `Debugger` object.
        It is used to forward the call to the first `ThreadContext` object."""
        if not self.threads:
            raise AttributeError(f"'Debugger' object has no attribute '{name}'")

        thread_context = next(iter(self.threads.values()))

        if not hasattr(thread_context, name):
            raise AttributeError(f"'Debugger' object has no attribute '{name}'")

        return getattr(thread_context, name)

    def __setattr__(self, name: str, value: object) -> None:
        """This function is called when an attribute is set in the `Debugger` object.
        It is used to forward the call to the first `ThreadContext` object."""
        # First we check if the attribute is available in the `Debugger` object
        if hasattr(Debugger, name):
            super().__setattr__(name, value)
        else:
            thread_context = next(iter(self.threads.values()))
            setattr(thread_context, name, value)

    def _peek_memory(self, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if debugging_context.running:
            raise RuntimeError("Cannot read memory while the process is running.")

        self._polling_thread_command_queue.put(
            (self.__threaded_peek_memory, (address,))
        )
        self._polling_thread_command_queue.join()

        value = self._polling_thread_response_queue.get()
        self._polling_thread_response_queue.task_done()

        if isinstance(value, BaseException):
            raise value

        return value

    def _poke_memory(self, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if debugging_context.running:
            raise RuntimeError("Cannot write memory while the process is running.")

        self._polling_thread_command_queue.put(
            (self.__threaded_poke_memory, (address, data))
        )
        self._polling_thread_command_queue.join()

    def _setup_memory_view(self):
        """Sets up the memory view of the process."""
        self.memory = MemoryView(
            self._peek_memory,
            self._poke_memory,
            self.interface.maps,
        )
        self._threaded_memory = MemoryView(
            self.__threaded_peek_memory,
            self.__threaded_poke_memory,
            self.interface.maps,
        )

        debugging_context.memory = self.memory
        debugging_context._threaded_memory = self._threaded_memory

    def _polling_thread_function(self):
        """This function is run in a thread. It is used to poll the process for state change."""
        while True:
            # Wait for the main thread to signal a command to execute
            command, args = self._polling_thread_command_queue.get()

            # Execute the command
            return_value = command(*args)

            if return_value is not None:
                self._polling_thread_response_queue.put(return_value)

            # Signal that the command has been executed
            self._polling_thread_command_queue.task_done()

            if return_value is not None:
                self._polling_thread_response_queue.join()

    def __threaded_run(self):
        liblog.debugger("Starting process %s.", debugging_context.argv[0])
        self.interface.run()

        debugging_context.set_stopped()

    def __threaded_attach(self, pid: int):
        liblog.debugger("Attaching to process %d.", pid)
        self.interface.attach(pid)

        debugging_context.set_stopped()

    def __threaded_kill(self):
        liblog.debugger("Killing process %s.", debugging_context.argv[0])
        self.interface.kill()

    def __threaded_cont(self):
        liblog.debugger("Continuing process %s.", debugging_context.argv[0])
        self.interface.cont()
        debugging_context.set_running()

    def __threaded_breakpoint(self, bp: Breakpoint):
        liblog.debugger("Setting breakpoint at 0x%x.", bp.address)
        self.interface.set_breakpoint(bp)

    def __threaded_wait(self):
        liblog.debugger("Waiting for process %s to stop.", debugging_context.argv[0])

        while self.interface.wait():
            self.interface.cont()

        debugging_context.set_stopped()

    def __threaded_step(self, thread: ThreadContext):
        liblog.debugger("Stepping thread %s.", thread.thread_id)
        self.interface.step(thread)
        debugging_context.set_running()

    def __threaded_step_until(
        self, thread: ThreadContext, address: int, max_steps: int
    ):
        liblog.debugger("Stepping thread %s until 0x%x.", thread.thread_id, address)
        self.interface.step_until(thread, address, max_steps)
        debugging_context.set_stopped()

    def __threaded_peek_memory(self, address: int) -> bytes:
        try:
            value = self.interface.peek_memory(address)
            # TODO: this is only for amd64
            return value.to_bytes(8, "little")
        except BaseException as e:
            return e

    def __threaded_poke_memory(self, address: int, data: bytes):
        data = int.from_bytes(data, "little")
        self.interface.poke_memory(address, data)


def debugger(
    argv: str | list[str] = None,
    enable_aslr: bool = False,
    env: dict[str, str] = None,
    continue_to_binary_entrypoint: bool = True,
) -> Debugger:
    """This function is used to create a new `Debugger` object. It takes as input the location of the binary to debug and returns a `Debugger` object.

    Args:
        argv (str | list[str]): The location of the binary to debug, and any additional arguments to pass to it.
        enable_aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to None.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.

    Returns:
        Debugger: The `Debugger` object.
    """
    if isinstance(argv, str):
        argv = [argv]

    debugging_context.clear()

    debugging_context.argv = argv
    debugging_context.env = env
    debugging_context.aslr_enabled = enable_aslr
    debugging_context.autoreach_entrypoint = continue_to_binary_entrypoint

    return Debugger()
