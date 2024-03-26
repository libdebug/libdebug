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
from pathlib import Path
import psutil
from queue import Queue
from subprocess import Popen
import time
from threading import Thread
from typing import Callable

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.interfaces.debugging_interface import DebuggingInterface
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.state.debugging_context import (
    DebuggingContext,
    context_extend_from,
    create_context,
    link_context,
    provide_context,
)
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.libcontext import libcontext

THREAD_TERMINATE = -1
GDB_GOBACK_LOCATION = str((Path(__file__).parent / "utils" / "gdb.py").resolve())


class _InternalDebugger:
    """The _InternalDebugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    memory: MemoryView | None = None
    """The memory view of the process."""

    breakpoints: dict[int, Breakpoint] = {}
    """A dictionary of all the breakpoints set on the process. The keys are the absolute addresses of the breakpoints."""

    context: DebuggingContext | None = None
    """The debugging context of the process."""

    instanced: bool = False
    """Whether the process was started and has not been killed yet."""

    interface: DebuggingInterface | None = None
    """The debugging interface used to interact with the process."""

    threads: list[ThreadContext] = []
    """A dictionary of all the threads in the process. The keys are the thread IDs."""

    _polling_thread: Thread | None = None
    """The background thread used to poll the process for state change."""

    _polling_thread_command_queue: Queue | None = None
    """The queue used to send commands to the background thread."""

    _polling_thread_response_queue: Queue | None = None
    """The queue used to receive responses from the background thread."""

    _threaded_memory: MemoryView | None = None
    """The memory view of the process, used for operations in the background thread."""

    def __init__(self):
        pass

    def _post_init_(self):
        """Do not use this constructor directly.
        Use the `debugger` function instead.
        """
        # validate that the binary exists
        if not os.path.isfile(provide_context(self).argv[0]):
            raise RuntimeError("The specified binary file does not exist.")

        self.context = provide_context(self)

        with context_extend_from(self):
            self.interface = provide_debugging_interface()
            self.context.debugging_interface = self.interface

        # threading utilities
        self._polling_thread_command_queue = Queue()
        self._polling_thread_response_queue = Queue()

        self.breakpoints = self.context.breakpoints
        self.threads = self.context.threads

        self._start_processing_thread()
        self._setup_memory_view()

    def terminate(self):
        """Terminates the background thread. The debugger object cannot be used after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        if self._polling_thread is not None:
            self._polling_thread_command_queue.put((THREAD_TERMINATE, ()))
            self._polling_thread.join()
            del self._polling_thread
            self._polling_thread = None

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

        assert self.context.pipe_manager is not None

        return self.context.pipe_manager

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

    def _ensure_process_stopped(self):
        """Validates the state of the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot continue.")

        if not self.context.running:
            return

        if self.context.auto_interrupt_on_command:
            self.context.interrupt()

        self._polling_thread_command_queue.join()

    def kill(self):
        """Kills the process."""
        try:
            self._ensure_process_stopped()
        except OSError:
            pass

        self._polling_thread_command_queue.put((self.__threaded_kill, ()))

        self.memory = None
        self.instanced = None

        if self.context.pipe_manager is not None:
            self.context.pipe_manager.close()
            self.context.pipe_manager = None

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        self.context.clear()
        self.interface.reset()

    def cont(self, auto_wait: bool = True):
        """Continues the process.

        Args:
            auto_wait (bool, optional): Whether to automatically wait for the process to stop after continuing. Defaults to True.
        """
        self._ensure_process_stopped()

        self._polling_thread_command_queue.put((self.__threaded_cont, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        if auto_wait:
            self._polling_thread_command_queue.put((self.__threaded_wait, ()))

    def interrupt(self):
        """Interrupts the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot interrupt.")

        if not self.context.running:
            return

        self.context.interrupt()

        self._polling_thread_command_queue.put((self.__threaded_wait, ()))
        self._polling_thread_command_queue.join()

    def wait(self):
        """Waits for the process to stop."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot wait.")

        # Wait for the background thread to signal "task done"
        # Our background might be waiting, and if so we must stop until it's done
        self._polling_thread_command_queue.join()

        if self.context.dead:
            raise RuntimeError("Process is dead.")

        if not self.context.running:
            return

        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def step(self, thread: ThreadContext | None = None):
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext, optional): The thread to step. Defaults to None.
        """
        self._ensure_process_stopped()

        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        self._polling_thread_command_queue.put((self.__threaded_step, (thread,)))
        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

    def step_until(
        self,
        position: int | str,
        thread: ThreadContext | None = None,
        max_steps: int = -1,
    ):
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            thread (ThreadContext, optional): The thread to step. Defaults to None.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        self._ensure_process_stopped()

        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        if isinstance(position, str):
            with context_extend_from(self):
                address = self.context.resolve_symbol(position)
        else:
            with context_extend_from(self):
                address = self.context.resolve_address(position)

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
        condition: str | None = None,
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. Defaults to None.
        """
        self._ensure_process_stopped()

        if isinstance(position, str):
            with context_extend_from(self):
                address = self.context.resolve_symbol(position)
        else:
            with context_extend_from(self):
                address = self.context.resolve_address(position)
            position = hex(address)

        if condition:
            if not hardware:
                raise ValueError(
                    "Breakpoint condition is supported only for hardware watchpoints."
                )

            if condition.lower() not in ["w", "rw", "x"]:
                raise ValueError(
                    "Invalid condition for watchpoints. Supported conditions are 'r', 'rw', 'x'."
                )

            if length not in [1, 2, 4, 8]:
                raise ValueError(
                    "Invalid length for watchpoints. Supported lengths are 1, 2, 4, 8."
                )

        if hardware and not condition:
            condition = "x"

        bp = Breakpoint(address, position, 0, hardware, callback, condition, length)

        link_context(bp, self)

        self._polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        # the breakpoint should have been set by interface
        assert address in self.breakpoints and self.breakpoints[address] is bp

        return bp

    def watchpoint(
        self,
        position: int | str,
        condition: str = "w",
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
    ) -> Breakpoint:
        """Sets a watchpoint at the specified location. Internally, watchpoints are implemented as breakpoints.

        Args:
            position (int | bytes): The location of the breakpoint.
            condition (str, optional): The trigger condition for the watchpoint (either "r", "rw" or "x"). Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the watchpoint is hit. Defaults to None.
        """
        return self.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
        )

    def migrate_to_gdb(self, open_in_new_process: bool = True):
        """Migrates the current debugging session to GDB."""
        self._ensure_process_stopped()

        self.context.interrupt()

        self._polling_thread_command_queue.put((self.__threaded_migrate_to_gdb, ()))

        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        if open_in_new_process and libcontext.terminal:
            self._open_gdb_in_new_process()  
        else:
            if open_in_new_process:
                liblog.warning("Cannot open in a new process. Please configure the terminal in libcontext.terminal.")
            self._open_gdb_in_shell()
        
        self._polling_thread_command_queue.put((self.__threaded_migrate_from_gdb, ()))
        self._polling_thread_command_queue.join()

        # We have to ignore a SIGSTOP signal that is sent by GDB
        # TODO: once we have signal handling, we should remove this
        self.cont()
        self.wait()

    def _open_gdb_in_new_process(self):
        """Opens GDB in a new process following the configuration in libcontext.terminal."""
        args = [
                "/bin/gdb", "-q",
                "--pid", str(self.context.process_id),
                "-ex", "source " + GDB_GOBACK_LOCATION,
                "-ex", "ni",
                "-ex", "ni",
        ]

        initial_pid = Popen(libcontext.terminal + args).pid

        os.waitpid(initial_pid, 0)

        liblog.debugger("Waiting for GDB process to terminate...")

        for proc in psutil.process_iter():
            cmdline = proc.cmdline()

            if args == cmdline:
                gdb_process = proc
                break
        else:
            raise RuntimeError("GDB process not found.")

        gdb_process.wait()    
    
    def _open_gdb_in_shell(self):
        """Open GDB in the current shell."""
        gdb_pid = os.fork()
        if gdb_pid == 0:  # This is the child process.
            args = [
                "/bin/gdb", "-q",
                "--pid", str(self.context.process_id),
                "-ex", "ni",
                "-ex", "ni",
            ]
            os.execv("/bin/gdb", args)
        else:  # This is the parent process.
            os.waitpid(gdb_pid, 0)  # Wait for the child process to finish.  

    def __getattr__(self, name: str) -> object:
        """This function is called when an attribute is not found in the `_InternalDebugger` object.
        It is used to forward the call to the first `ThreadContext` object."""
        if not self.threads:
            raise AttributeError(f"'debugger has no attribute '{name}'")

        self._ensure_process_stopped()

        thread_context = self.threads[0]

        if not hasattr(thread_context, name):
            raise AttributeError(f"'debugger has no attribute '{name}'")

        return getattr(thread_context, name)

    def __setattr__(self, name: str, value: object) -> None:
        """This function is called when an attribute is set in the `_InternalDebugger` object.
        It is used to forward the call to the first `ThreadContext` object."""
        # First we check if the attribute is available in the `_InternalDebugger` object
        if hasattr(_InternalDebugger, name):
            super().__setattr__(name, value)
        else:
            self._ensure_process_stopped()
            thread_context = self.threads[0]
            setattr(thread_context, name, value)

    def _peek_memory(self, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if self.context.running:
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

        if self.context.running:
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

        self.context.memory = self.memory
        self.context._threaded_memory = self._threaded_memory

    def _polling_thread_function(self):
        """This function is run in a thread. It is used to poll the process for state change."""
        while True:
            # Wait for the main thread to signal a command to execute
            command, args = self._polling_thread_command_queue.get()

            if command == THREAD_TERMINATE:
                # Signal that the command has been executed
                self._polling_thread_command_queue.task_done()
                return

            # Execute the command
            return_value = command(*args)

            if return_value is not None:
                self._polling_thread_response_queue.put(return_value)

            # Signal that the command has been executed
            self._polling_thread_command_queue.task_done()

            if return_value is not None:
                self._polling_thread_response_queue.join()

    def __threaded_run(self):
        liblog.debugger("Starting process %s.", self.context.argv[0])
        self.interface.run()

        self.context.set_stopped()

    def __threaded_attach(self, pid: int):
        liblog.debugger("Attaching to process %d.", pid)
        self.interface.attach(pid)

        self.context.set_stopped()

    def __threaded_kill(self):
        liblog.debugger("Killing process %s.", self.context.argv[0])
        self.interface.kill()

    def __threaded_cont(self):
        liblog.debugger("Continuing process %s.", self.context.argv[0])
        self.interface.cont()
        self.context.set_running()

    def __threaded_breakpoint(self, bp: Breakpoint):
        liblog.debugger("Setting breakpoint at 0x%x.", bp.address)
        self.interface.set_breakpoint(bp)

    def __threaded_wait(self):
        liblog.debugger("Waiting for process %s to stop.", self.context.argv[0])

        while self.interface.wait():
            self.interface.cont()

        self.context.set_stopped()

    def __threaded_step(self, thread: ThreadContext):
        liblog.debugger("Stepping thread %s.", thread.thread_id)
        self.interface.step(thread)
        self.context.set_running()

    def __threaded_step_until(
        self, thread: ThreadContext, address: int, max_steps: int
    ):
        liblog.debugger("Stepping thread %s until 0x%x.", thread.thread_id, address)
        self.interface.step_until(thread, address, max_steps)
        self.context.set_stopped()

    def __threaded_peek_memory(self, address: int) -> bytes | BaseException:
        try:
            value = self.interface.peek_memory(address)
            # TODO: this is only for amd64
            return value.to_bytes(8, "little")
        except BaseException as e:
            return e

    def __threaded_poke_memory(self, address: int, data: bytes):
        int_data = int.from_bytes(data, "little")
        self.interface.poke_memory(address, int_data)

    def __threaded_migrate_to_gdb(self):
        self.interface.migrate_to_gdb()

    def __threaded_migrate_from_gdb(self):
        self.interface.migrate_from_gdb()


def debugger(
    argv: str | list[str],
    enable_aslr: bool = False,
    env: dict[str, str] | None = None,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = True,
) -> _InternalDebugger:
    """This function is used to create a new `_InternalDebugger` object. It takes as input the location of the binary to debug and returns a `_InternalDebugger` object.

    Args:
        argv (str | list[str]): The location of the binary to debug, and any additional arguments to pass to it.
        enable_aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to True.

    Returns:
        _InternalDebugger: The `_InternalDebugger` object.
    """
    if isinstance(argv, str):
        argv = [argv]

    debugger = _InternalDebugger()

    debugging_context = create_context(debugger)

    debugging_context.clear()

    if not env:
        env = os.environ

    debugging_context.argv = argv
    debugging_context.env = env
    debugging_context.aslr_enabled = enable_aslr
    debugging_context.autoreach_entrypoint = continue_to_binary_entrypoint
    debugging_context.auto_interrupt_on_command = auto_interrupt_on_command

    debugger._post_init_()

    return debugger
