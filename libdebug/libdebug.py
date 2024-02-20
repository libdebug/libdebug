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

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.state.process_context import ProcessContext
from libdebug.state.thread_context import ThreadContext
from libdebug.state.process.process_context_provider import provide_process_context
from libdebug.interfaces.interface_helper import debugging_interface_provider
from libdebug.liblog import liblog
from libdebug.utils.pipe_manager import PipeManager
import os
from queue import Queue
from threading import Thread
from typing import Callable


class Debugger:
    """The Debugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    breakpoints: dict[int, Breakpoint] = None
    """A dictionary of all the breakpoints set on the process. The keys are the absolute addresses of the breakpoints."""

    memory: MemoryView = None
    """The memory view of the process."""

    process_context: ProcessContext
    """The process context object."""

    threads: dict[int, ThreadContext]
    """A dictionary of all the threads in the process. The keys are the thread IDs."""

    def __init__(self, argv, enable_aslr, env):
        """Do not use this constructor directly.
        Use the `debugger` function instead.
        """
        if isinstance(argv, str):
            self.argv = [argv]
        else:
            self.argv = argv

        # validate that the binary exists
        if not os.path.isfile(self.argv[0]):
            raise RuntimeError("Binary file does not exist.")

        self.enable_aslr = enable_aslr
        self.env = env

        # instanced is True if and only if the process has been started and has not been killed yet
        self.instanced = False
        self.interface = debugging_interface_provider(
            self._create_new_thread, self._delete_thread
        )
        self.stack_unwinder = stack_unwinding_provider()

        if not enable_aslr:
            self.interface.disable_aslr()

        # threading utilities
        self._polling_thread: Thread | None = None
        self._polling_thread_command_queue: Queue = Queue()

        # TODO don't share this using a property
        self._pipe_manager: PipeManager = None

        # instance breakpoints dict
        self.breakpoints = {}

        self.process_context = None
        self.threads = {}

        self._start_processing_thread()

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

        return self._pipe_manager

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
        self.process_context = None
        self._pipe_manager.close()
        self._pipe_manager = None

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def cont(self):
        """Continues the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot continue.")

        if self.process_context.dead or self.process_context.running:
            raise RuntimeError("Process is dead or already running.")

        self._polling_thread_command_queue.put((self.__threaded_cont, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def wait(self):
        """Waits for the process to stop."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot wait.")

        if self.process_context.dead or not self.process_context.running:
            raise RuntimeError("Process is dead or not running.")

        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def step(self):
        """Executes a single instruction of the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        self._polling_thread_command_queue.put((self.__threaded_step, ()))
        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def breakpoint(
        self,
        position: int | str,
        hardware: bool = False,
        callback: None | Callable[["Debugger", Breakpoint], None] = None,
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
        """
        if self.process_context.running:
            raise RuntimeError("Cannot set a breakpoint while the process is running.")

        if isinstance(position, str):
            address = self.process_context.resolve_symbol(position)
        else:
            address = self.process_context.resolve_address(position)
            position = address

        bp = Breakpoint(address, position, 0, hardware, callback)

        self.breakpoints[address] = bp

        self._polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        return bp

    def _polling_thread_function(self):
        """This function is run in a thread. It is used to poll the process for state change."""
        while True:
            # Wait for the main thread to signal a command to execute
            command, args = self._polling_thread_command_queue.get()

            # Execute the command
            command(*args)

            # Signal that the command has been executed
            self._polling_thread_command_queue.task_done()

    def _create_new_thread(self, thread_id: int):
        """Creates a new thread context object."""
        thread = ThreadContext.new(self.process_context, thread_id)
        self.threads[thread.thread_id] = thread

        liblog.debugger("Thread %d created.", thread.thread_id)

        return thread

    def _delete_thread(self, thread_id: int):
        """Deletes a thread context object."""
        if thread_id in self.threads:
            del self.threads[thread_id]

            liblog.debugger("Thread %d deleted.", thread_id)

        if self.threads == {}:
            self.process_context.set_dead()

    def __threaded_run(self):
        liblog.debugger("Starting process %s.", self.argv[0])
        self._pipe_manager = self.interface.run(self.argv, self.enable_aslr, self.env)

        self.process_context = provide_process_context(self.interface, self.argv)
        self.process_context.set_stopped()

        # create and update main thread context
        main_thread = self._create_new_thread(None)

        main_thread._poll_registers()

        # create memory view
        self.memory = self.interface.provide_memory_view()
        if self.memory.maps_provider is None:
            # TODO: not really the best way to do this
            self.memory.maps_provider = self.process_context.maps

    def __threaded_kill(self):
        liblog.debugger("Killing process %s.", self.argv[0])
        self.interface.kill()

    def __threaded_cont(self):
        liblog.debugger("Continuing process %s.", self.argv[0])
        self.interface.cont()
        self.process_context.set_running()

    def __threaded_breakpoint(self, bp: Breakpoint):
        liblog.debugger("Setting breakpoint at 0x%x.", bp.address)
        self.interface.set_breakpoint(bp)

    def __threaded_wait(self):
        liblog.debugger("Waiting for process %s to stop.", self.argv[0])
        self.interface.wait()

        self.process_context.set_stopped()

        # Update the state of the process and its threads
        keys = list(self.threads.keys())
        for thread_id in keys:
            if thread_id in self.threads:
                self.threads[thread_id]._poll_registers()

    def __threaded_step(self):
        liblog.debugger("Stepping process %s.", self.argv[0])
        self.interface.step()
        self.process_context.set_running()


def debugger(
    argv: str | list[str] = None, enable_aslr: bool = False, env: dict[str, str] = None
) -> Debugger:
    """This function is used to create a new `Debugger` object. It takes as input the location of the binary to debug and returns a `Debugger` object.

    Args:
        argv (str | list[str]): The location of the binary to debug, and any additional arguments to pass to it.
        enable_aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to None.

    Returns:
        Debugger: The `Debugger` object.
    """

    return Debugger(argv, enable_aslr, env)
