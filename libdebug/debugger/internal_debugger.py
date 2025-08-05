#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


from __future__ import annotations

import functools
import os
import signal
import sys
from pathlib import Path
from queue import Queue
from signal import SIGKILL, SIGSTOP, SIGTRAP
from subprocess import DEVNULL, CalledProcessError, Popen, check_call
from tempfile import NamedTemporaryFile
from threading import Event, Thread, current_thread
from typing import TYPE_CHECKING

from psutil import STATUS_ZOMBIE, Error, Process, ZombieProcess, process_iter

from libdebug.architectures.breakpoint_validator import validate_hardware_breakpoint
from libdebug.architectures.syscall_hijacker import SyscallHijacker
from libdebug.builtin.antidebug_syscall_handler import on_enter_ptrace, on_exit_ptrace
from libdebug.builtin.pretty_print_syscall_handler import (
    pprint_on_enter,
    pprint_on_exit,
)
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.gdb_resume_event import GdbResumeEvent
from libdebug.data.signal_catcher import SignalCatcher
from libdebug.data.syscall_handler import SyscallHandler
from libdebug.data.terminals import TerminalTypes
from libdebug.debugger.debugger import Debugger
from libdebug.debugger.internal_debugger_instance_manager import (
    extend_internal_debugger,
    link_to_internal_debugger,
    remove_internal_debugger_refs,
)
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.memory.chunked_memory_view import ChunkedMemoryView
from libdebug.memory.direct_memory_view import DirectMemoryView
from libdebug.memory.process_memory_manager import ProcessMemoryManager
from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
from libdebug.snapshots.serialization.serialization_helper import SerializationHelper
from libdebug.state.resume_context import ResumeContext
from libdebug.utils.arch_mappings import map_arch
from libdebug.utils.argument_list import ArgumentList
from libdebug.utils.debugger_wrappers import (
    background_alias,
    change_state_function_process,
    change_state_function_thread,
)
from libdebug.utils.debugging_utils import (
    normalize_and_validate_address,
    resolve_symbol_in_maps,
)
from libdebug.utils.elf_utils import get_all_symbols
from libdebug.utils.file_utils import ensure_file_executable
from libdebug.utils.libcontext import libcontext
from libdebug.utils.platform_utils import get_platform_gp_register_size
from libdebug.utils.pprint_primitives import pprint_maps_util, pprint_memory_util
from libdebug.utils.signal_utils import (
    resolve_signal_name,
    resolve_signal_number,
)
from libdebug.utils.syscall_utils import (
    get_all_syscall_numbers,
    resolve_syscall_name,
    resolve_syscall_number,
)
from libdebug.utils.thread_exceptions import raise_exception_to_main_thread

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from libdebug.commlink.pipe_manager import PipeManager
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.data.registers import Registers
    from libdebug.data.symbol import Symbol
    from libdebug.data.symbol_list import SymbolList
    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.memory.abstract_memory_view import AbstractMemoryView
    from libdebug.snapshots.snapshot import Snapshot
    from libdebug.state.thread_context import ThreadContext

THREAD_TERMINATE = -1
GDB_GOBACK_LOCATION = str((Path(__file__).parent.parent / "utils" / "gdb.py").resolve())


class InternalDebugger:
    """A class that holds the global debugging state."""

    aslr_enabled: bool
    """A flag that indicates if ASLR is enabled or not."""

    arch: str
    """The architecture of the debugged process."""

    argv: ArgumentList
    """The command line arguments of the debugged process."""

    path: str
    """The path to the binary of the debugged process."""

    env: dict[str, str] | None
    """The environment variables of the debugged process."""

    escape_antidebug: bool
    """A flag that indicates if the debugger should escape anti-debugging techniques."""

    fast_memory: bool
    """A flag that indicates if the debugger should use a faster memory access method."""

    autoreach_entrypoint: bool
    """A flag that indicates if the debugger should automatically reach the entry point of the debugged process."""

    auto_interrupt_on_command: bool
    """A flag that indicates if the debugger should automatically interrupt the debugged process when a command is issued."""

    follow_children: bool
    """A flag that indicates if the debugger should follow child processes creating a new debugger for each one."""

    breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process. Key: the address of the breakpoint."""

    handled_syscalls: dict[int, SyscallHandler]
    """A dictionary of all the syscall handled in the process. Key: the syscall number."""

    caught_signals: dict[int, SignalCatcher]
    """A dictionary of all the signals caught in the process. Key: the signal number."""

    signals_to_block: list[int]
    """The signals to not forward to the process."""

    syscalls_to_pprint: list[int] | None
    """The syscalls to pretty print."""

    syscalls_to_not_pprint: list[int] | None
    """The syscalls to not pretty print."""

    kill_on_exit: bool
    """A flag that indicates if the debugger should kill the debugged process when it exits."""

    threads: list[ThreadContext]
    """A list of all the threads of the debugged process."""

    process_id: int
    """The PID of the debugged process."""

    pipe_manager: PipeManager
    """The PipeManager used to communicate with the debugged process."""

    memory: AbstractMemoryView
    """The memory view of the debugged process."""

    debugging_interface: DebuggingInterface
    """The debugging interface used to communicate with the debugged process."""

    instanced: bool = False
    """Whether the process was started and has not been killed yet."""

    is_debugging: bool = False
    """Whether the debugger is currently debugging a process."""

    children: list[Debugger]
    """The list of child debuggers."""

    pprint_syscalls: bool
    """A flag that indicates if the debugger should pretty print syscalls."""

    resume_context: ResumeContext
    """Context that indicates if the debugger should resume the debugged process."""

    debugger: Debugger
    """The debugger object."""

    stdin_settings_backup: list[Any]
    """The backup of the stdin settings. Used to restore the original settings after possible conflicts due to the pipe manager interacactive mode."""

    __polling_thread: Thread | None
    """The background thread used to poll the process for state change."""

    __polling_thread_command_queue: Queue | None
    """The queue used to send commands to the background thread."""

    __polling_thread_response_queue: Queue | None
    """The queue used to receive responses from the background thread."""

    __timeout_thread: Thread | None
    """The thread used to kill the debuggee on timeout."""

    __timeout_thread_command_queue: Queue | None
    """The queue used to send commands to the timeout thread."""

    __timeout_thread_conditional: Event | None
    """The condition variable the timeout thread waits on."""

    _is_running: bool
    """The overall state of the debugged process. True if the process is running, False otherwise."""

    _is_migrated_to_gdb: bool
    """A flag that indicates if the debuggee was migrated to GDB."""

    _gdb_resume_event: GdbResumeEvent
    """The GDB resume event used to migrate the debugged process back from GDB."""

    _fast_memory: DirectMemoryView
    """The memory view of the debugged process using the fast memory access method."""

    _slow_memory: ChunkedMemoryView
    """The memory view of the debugged process using the slow memory access method."""

    _snapshot_count: int
    """The counter used to assign an ID to each snapshot."""

    _has_path_different_from_argv0: bool
    """A flag that indicates if the path to the binary is different from the first argument in argv."""

    def __init__(self: InternalDebugger) -> None:
        """Initialize the context."""
        # These must be reinitialized on every call to "debugger"
        self.aslr_enabled = False
        self.autoreach_entrypoint = True
        self.argv = ArgumentList()
        self.env = {}
        self.escape_antidebug = False
        self.breakpoints = {}
        self.handled_syscalls = {}
        self.caught_signals = {}
        self.syscalls_to_pprint = None
        self.syscalls_to_not_pprint = None
        self.signals_to_block = []
        self.pprint_syscalls = False
        self.pipe_manager = None
        self.process_id = 0
        self.threads = []
        self.instanced = False
        self.is_debugging = False
        self._is_running = False
        self._is_migrated_to_gdb = False
        self._gdb_resume_event = None
        self.resume_context = ResumeContext()
        self.stdin_settings_backup = []
        self.arch = map_arch(libcontext.platform)
        self.kill_on_exit = True
        self._process_memory_manager = ProcessMemoryManager()
        self.fast_memory = True
        self.__polling_thread_command_queue = Queue()
        self.__polling_thread_response_queue = Queue()
        self.__timeout_thread = None
        self._snapshot_count = 0
        self.serialization_helper = SerializationHelper()
        self.children = []

    def clear(self: InternalDebugger) -> None:
        """Reinitializes the context, so it is ready for a new run."""
        # These must be reinitialized on every call to "run"
        self.breakpoints.clear()
        self.handled_syscalls.clear()
        self.caught_signals.clear()
        self.syscalls_to_pprint = None
        self.syscalls_to_not_pprint = None
        self.signals_to_block.clear()
        self.pprint_syscalls = False
        self.pipe_manager = None
        self.process_id = 0

        for t in self.threads:
            del t.regs.register_file
            del t.regs._fp_register_file

        self.threads.clear()
        self.instanced = False
        self.is_debugging = False
        self._is_running = False
        self.resume_context.clear()
        self.children.clear()

    def start_up(self: InternalDebugger) -> None:
        """Starts up the context."""
        # The context is linked to itself
        link_to_internal_debugger(self, self)

        self.start_processing_thread()
        with extend_internal_debugger(self):
            self.debugging_interface = provide_debugging_interface()
            self._fast_memory = DirectMemoryView(self._fast_read_memory, self._fast_write_memory)
            self._slow_memory = ChunkedMemoryView(
                self._peek_memory,
                self._poke_memory,
                unit_size=get_platform_gp_register_size(libcontext.platform),
            )

    def start_processing_thread(self: InternalDebugger) -> None:
        """Starts the thread that will poll the traced process for state change."""
        # Set as daemon so that the Python interpreter can exit even if the thread is still running
        self.__polling_thread = Thread(
            target=self.__polling_thread_function,
            name="libdebug__polling_thread",
            daemon=True,
        )
        self.__polling_thread.start()

    def _background_invalid_call(self: InternalDebugger, *_: ..., **__: ...) -> None:
        """Raises an error when an invalid call is made in background mode."""
        raise RuntimeError("This method is not available in a callback.")

    def run(self: InternalDebugger, timeout: float = -1, redirect_pipes: bool = True) -> PipeManager | None:
        """Starts the process and waits for it to stop.

        Args:
            timeout (float): The timeout in seconds. If -1, no timeout is set.
            redirect_pipes (bool): Whether to hook and redirect the pipes of the process to a PipeManager.
        """
        if not self.argv:
            raise RuntimeError("No binary file specified.")

        if timeout <= 0 and timeout != -1:
            raise ValueError("Timeout must be a positive number or -1.")
        if 0 < timeout <= 0.01:
            liblog.warning("Timeout is set to a very low value. This may cause issues.")

        ensure_file_executable(self.path)

        if self.is_debugging:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.threads:
            self.clear()

        self.debugging_interface.reset()

        self.instanced = True
        self.is_debugging = True

        if not self.__polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self.__polling_thread_command_queue.put((self.__threaded_run, (redirect_pipes,)))

        self._join_and_check_status()

        if self.escape_antidebug:
            liblog.debugger("Enabling anti-debugging escape mechanism.")
            self._enable_antidebug_escaping()

        if timeout > 0:
            self.enqueue_timeout_command(timeout)

        if redirect_pipes and not self.pipe_manager:
            raise RuntimeError("Something went wrong during pipe initialization.")

        self._process_memory_manager.open(self.process_id)

        return self.pipe_manager

    def attach(self: InternalDebugger, pid: int) -> None:
        """Attaches to an existing process."""
        if self.is_debugging:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.threads:
            self.clear()
            self.debugging_interface.reset()

        self.instanced = True
        self.is_debugging = True

        if not self.__polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self.__polling_thread_command_queue.put((self.__threaded_attach, (pid,)))

        self._join_and_check_status()

        self._process_memory_manager.open(self.process_id)

    def detach(self: InternalDebugger) -> None:
        """Detaches from the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot detach.")

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put((self.__threaded_detach, ()))

        self.is_debugging = False

        self._join_and_check_status()

        self._process_memory_manager.close()

    def set_child_debugger(self: InternalDebugger, child_pid: int) -> None:
        """Sets the child debugger after a fork.

        Args:
            child_pid (int): The PID of the child process.
        """
        # Create a new InternalDebugger instance for the child process with the same configuration
        # of the parent debugger
        child_internal_debugger = InternalDebugger()
        child_internal_debugger.argv = self.argv
        child_internal_debugger.path = self.path
        child_internal_debugger.env = self.env
        child_internal_debugger.aslr_enabled = self.aslr_enabled
        child_internal_debugger.autoreach_entrypoint = self.autoreach_entrypoint
        child_internal_debugger.auto_interrupt_on_command = self.auto_interrupt_on_command
        child_internal_debugger.escape_antidebug = self.escape_antidebug
        child_internal_debugger.fast_memory = self.fast_memory
        child_internal_debugger.kill_on_exit = self.kill_on_exit
        child_internal_debugger.follow_children = self.follow_children

        # Create the new Debugger instance for the child process
        child_debugger = Debugger()
        child_debugger.post_init_(child_internal_debugger)
        child_internal_debugger.debugger = child_debugger
        child_debugger.arch = self.arch

        # Attach to the child process with the new debugger
        child_internal_debugger.attach(child_pid)
        self.children.append(child_debugger)
        liblog.debugger(
            "Child process with pid %d registered to the parent debugger (pid %d)",
            child_pid,
            self.process_id,
        )

    @background_alias(_background_invalid_call)
    def kill(self: InternalDebugger) -> None:
        """Kills the process."""
        if not self.is_debugging:
            raise RuntimeError("No process currently debugged, cannot kill.")

        self._ensure_process_stopped()

        self._process_memory_manager.close()

        self.__polling_thread_command_queue.put((self.__threaded_kill, ()))

        self.instanced = False
        self.is_debugging = False

        self.set_all_threads_as_dead()

        if self.pipe_manager:
            self.pipe_manager.close()

        self._join_and_check_status()

    def _atexit_terminate(self: InternalDebugger) -> None:
        """Terminate the background threads with an aggressive approach. This is meant to be used in atexit handlers."""
        if self.__polling_thread is not None:
            # When the main thread terminates, the polling thread will be terminated as well in any case,
            # as it is a daemon thread. However, the nanobind C++ exit handler might race with the Python
            # atexit handler defined by us. In that case, we might see an error message of the type
            # `terminate called without an active exception` with a consequent core dump.
            # This has no real consequences, but it is annoying and inelegant. To avoid, as much as possible,
            # this behavior, we send a command to the polling thread to terminate. However, the polling thread
            # might be stuck in an endless callback or waiting for an event that will never happen due to some
            # edge cases we missed. Since we MUST finish the execution of the script as soon as possible, we call
            # join() on it with a reasonable timeout. If it does terminate in time, we are sure that everything is
            # fine and we will have no race. If not, the other thread is probably stuck. The race might still happen,
            # but it is less likely.
            self.__polling_thread_command_queue.put((THREAD_TERMINATE, ()))
            self.__polling_thread.join(0.5)
            if self.__polling_thread.is_alive():
                liblog.debugger("Polling thread is still alive after THREAD_TERMINATE. It might be stuck.")

        if self.__timeout_thread is not None:
            # It is unlikely that the timeout thread gets stuck, but we use the same approach here. Just to be sure.
            self.__timeout_thread_command_queue.put(THREAD_TERMINATE)
            self.__timeout_thread.join(0.5)
            if self.__timeout_thread.is_alive():
                liblog.debugger("Timeout thread is still alive after THREAD_TERMINATE. It might be stuck.")

    def terminate(self: InternalDebugger) -> None:
        """Interrupts the process, kills it and then terminates the background thread.

        The debugger object will not be usable after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        if self.instanced and self.running:
            try:
                self.interrupt()
            except ProcessLookupError:
                # The process has already been killed by someone or something else
                liblog.debugger("Interrupting process failed: already terminated")

        if self.instanced and self.is_debugging:
            try:
                self.kill()
            except ProcessLookupError:
                # The process has already been killed by someone or something else
                liblog.debugger("Killing process failed: already terminated")

        self.instanced = False
        self.is_debugging = False

        if self.__polling_thread is not None:
            self.__polling_thread_command_queue.put((THREAD_TERMINATE, ()))
            self.__polling_thread.join()
            del self.__polling_thread
            self.__polling_thread = None

        self.cleanup_timeout_thread()

        # Remove elemement from internal_debugger_holder to avoid memleaks
        remove_internal_debugger_refs(self)

        # Clean up the register accessors
        for thread in self.threads:
            thread._register_holder.cleanup()

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def cont(self: InternalDebugger) -> None:
        """Continues the process."""
        self.__polling_thread_command_queue.put((self.__threaded_cont, ()))

        self._join_and_check_status()

        self.__polling_thread_command_queue.put((self.__threaded_wait, ()))

    def _background_interrupt(self: InternalDebugger) -> None:
        """Interrupts the process in the background."""
        self.resume_context.resume = False

    @background_alias(_background_interrupt)
    def interrupt(self: InternalDebugger) -> None:
        """Interrupts the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot interrupt.")

        # We have to ensure that at least one thread is alive before executing the method
        if self.threads[0].dead:
            raise RuntimeError("All threads are dead.")

        if not self.running:
            return

        self.resume_context.force_interrupt = True
        os.kill(self.process_id, SIGSTOP)

        self.wait()

    @background_alias(_background_invalid_call)
    def wait(self: InternalDebugger) -> None:
        """Waits for the process to stop."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot wait.")

        self._join_and_check_status()

        if self.threads[0].dead or not self.running:
            # Most of the time the function returns here, as there was a wait already
            # queued by the previous command
            return

        self.__polling_thread_command_queue.put((self.__threaded_wait, ()))

        self._join_and_check_status()

    @property
    @change_state_function_process
    def maps(self: InternalDebugger) -> MemoryMapList[MemoryMap]:
        """Returns the memory maps of the process."""
        return self.debugging_interface.get_maps()

    @property
    @change_state_function_process
    def memory(self: InternalDebugger) -> AbstractMemoryView:
        """The memory view of the debugged process."""
        return self._fast_memory if self.fast_memory else self._slow_memory

    def pprint_maps(self: InternalDebugger) -> None:
        """Prints the memory maps of the process."""
        pprint_maps_util(self.maps)

    def pprint_memory(
        self: InternalDebugger,
        start: int,
        end: int,
        file: str = "hybrid",
        override_word_size: int | None = None,
        integer_mode: bool = False,
    ) -> None:
        """Pretty print the memory diff.

        Args:
            start (int): The start address of the memory diff.
            end (int): The end address of the memory diff.
            file (str, optional): The backing file for relative / absolute addressing. Defaults to "hybrid".
            override_word_size (int, optional): The word size to use for the diff in place of the ISA word size. Defaults to None.
            integer_mode (bool, optional): If True, the diff will be printed as hex integers (system endianness applies). Defaults to False.
        """
        if start > end:
            tmp = start
            start = end
            end = tmp

        word_size = get_platform_gp_register_size(self.arch) if override_word_size is None else override_word_size

        # Resolve the address
        if file == "absolute":
            address_start = start
        elif file == "hybrid":
            try:
                # Try to resolve the address as absolute
                self.memory[start, 1, "absolute"]
                address_start = start
            except ValueError:
                # If the address is not in the maps, we use the binary file
                address_start = start + self.maps.filter("binary")[0].start
                file = "binary"
        else:
            map_file = self.maps.filter(file)[0]
            address_start = start + map_file.base
            file = map_file.backing_file if file != "binary" else "binary"

        extract = self.memory[start:end, file]

        file_info = f" (file: {file})" if file not in ("absolute", "hybrid") else ""
        print(f"Memory from {start:#x} to {end:#x}{file_info}:")

        pprint_memory_util(
            address_start,
            extract,
            word_size,
            self.maps,
            integer_mode=integer_mode,
        )

    @change_state_function_process
    def breakpoint(
        self: InternalDebugger,
        position: int | str,
        hardware: bool = False,
        condition: str = "x",
        length: int = 1,
        callback: None | bool | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (None | bool | Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. If True, an empty callback will be set. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)
            position = hex(address)

        if condition != "x" and not hardware:
            raise ValueError("Breakpoint condition is supported only for hardware watchpoints.")

        if callback is True:

            def callback(_: ThreadContext, __: Breakpoint) -> None:
                pass

        bp = Breakpoint(address, position, 0, hardware, callback, condition.lower(), length)

        if hardware:
            validate_hardware_breakpoint(self.arch, bp)

        link_to_internal_debugger(bp, self)

        if not self._is_in_background():
            # Go through the queue and wait for it to be done
            self.__polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))
            self._join_and_check_status()
        else:
            # Let's do this ourselves and move on
            self.__threaded_breakpoint(bp)

        # the breakpoint should have been set by interface
        if address not in self.breakpoints:
            raise RuntimeError("Something went wrong while inserting the breakpoint.")

        return bp

    @change_state_function_process
    def catch_signal(
        self: InternalDebugger,
        signal: int | str,
        callback: None | bool | Callable[[ThreadContext, SignalCatcher], None] = None,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Catch a signal in the target process.

        Args:
            signal (int | str): The signal to catch. If "*", "ALL", "all" or -1 is passed, all signals will be caught.
            callback (None | bool | Callable[[ThreadContext, SignalCatcher], None], optional): A callback to be called when the signal is caught. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.

        Returns:
            SignalCatcher: The SignalCatcher object.
        """
        if isinstance(signal, str):
            signal_number = resolve_signal_number(signal)
        elif isinstance(signal, int):
            signal_number = signal
        else:
            raise TypeError("signal must be an int or a str")

        match signal_number:
            case SIGKILL.value:
                raise ValueError(
                    f"Cannot catch SIGKILL ({signal_number}) as it cannot be caught or ignored. This is a kernel restriction.",
                )
            case SIGSTOP.value:
                raise ValueError(
                    f"Cannot catch SIGSTOP ({signal_number}) as it is used by the debugger or ptrace for their internal operations.",
                )
            case SIGTRAP.value:
                liblog.warning(
                    f"Catching SIGTRAP ({signal_number}) may interfere with libdebug operations as it is used by the debugger or ptrace for their internal operations. Use with care."
                )

        if signal_number in self.caught_signals:
            liblog.warning(
                f"Signal {resolve_signal_name(signal_number)} ({signal_number}) has already been caught. Overriding it.",
            )

        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")

        if callback is True:

            def callback(_: ThreadContext, __: SignalCatcher) -> None:
                pass

        catcher = SignalCatcher(signal_number, callback, recursive)

        link_to_internal_debugger(catcher, self)

        if not self._is_in_background():
            # Go through the queue and wait for it to be done
            self.__polling_thread_command_queue.put((self.__threaded_catch_signal, (catcher,)))
            self._join_and_check_status()
        else:
            # Let's do this ourselves and move on
            self.__threaded_catch_signal(catcher)

        return catcher

    @change_state_function_process
    def hijack_signal(
        self: InternalDebugger,
        original_signal: int | str,
        new_signal: int | str,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Hijack a signal in the target process.

        Args:
            original_signal (int | str): The signal to hijack. If "*", "ALL", "all" or -1 is passed, all signals will be hijacked.
            new_signal (int | str): The signal to hijack the original signal with.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.

        Returns:
            SignalCatcher: The SignalCatcher object.
        """
        if isinstance(original_signal, str):
            original_signal_number = resolve_signal_number(original_signal)
        else:
            original_signal_number = original_signal

        new_signal_number = resolve_signal_number(new_signal) if isinstance(new_signal, str) else new_signal

        if new_signal_number == -1:
            raise ValueError("Cannot hijack a signal with the 'ALL' signal.")

        if original_signal_number == new_signal_number:
            raise ValueError(
                "The original signal and the new signal must be different during hijacking.",
            )

        def callback(thread: ThreadContext, _: SignalCatcher) -> None:
            """The callback to execute when the signal is received."""
            thread.signal = new_signal_number

        return self.catch_signal(original_signal_number, callback, recursive)

    @change_state_function_process
    def handle_syscall(
        self: InternalDebugger,
        syscall: int | str,
        on_enter: Callable[[ThreadContext, SyscallHandler], None] | None = None,
        on_exit: Callable[[ThreadContext, SyscallHandler], None] | None = None,
        recursive: bool = False,
    ) -> SyscallHandler:
        """Handle a syscall in the target process.

        Args:
            syscall (int | str): The syscall name or number to handle. If "*", "ALL", "all", or -1 is passed, all syscalls will be handled.
            on_enter (None | bool |Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is entered. If True, an empty callback will be set. Defaults to None.
            on_exit (None | bool | Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is exited. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.

        Returns:
            SyscallHandler: The SyscallHandler object.
        """
        syscall_number = resolve_syscall_number(self.arch, syscall) if isinstance(syscall, str) else syscall

        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")

        if on_enter is True:

            def on_enter(_: ThreadContext, __: SyscallHandler) -> None:
                pass

        if on_exit is True:

            def on_exit(_: ThreadContext, __: SyscallHandler) -> None:
                pass

        # Check if the syscall is already handled (by the user or by the pretty print handler)
        if syscall_number in self.handled_syscalls:
            handler = self.handled_syscalls[syscall_number]
            if handler.on_enter_user or handler.on_exit_user:
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, syscall_number)} is already handled by a user-defined handler. Overriding it.",
                )
            handler.on_enter_user = on_enter
            handler.on_exit_user = on_exit
            handler.recursive = recursive
            handler.enabled = True
        else:
            handler = SyscallHandler(
                syscall_number,
                on_enter,
                on_exit,
                None,
                None,
                recursive,
            )

            link_to_internal_debugger(handler, self)

            if not self._is_in_background():
                # Go through the queue and wait for it to be done
                self.__polling_thread_command_queue.put(
                    (self.__threaded_handle_syscall, (handler,)),
                )
                self._join_and_check_status()
            else:
                # Let's do this ourselves and move on
                self.__threaded_handle_syscall(handler)

        return handler

    @change_state_function_process
    def hijack_syscall(
        self: InternalDebugger,
        original_syscall: int | str,
        new_syscall: int | str,
        recursive: bool = True,
        **kwargs: int,
    ) -> SyscallHandler:
        """Hijacks a syscall in the target process.

        Args:
            original_syscall (int | str): The syscall name or number to hijack. If "*", "ALL", "all" or -1 is passed, all syscalls will be hijacked.
            new_syscall (int | str): The syscall name or number to hijack the original syscall with.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.
            **kwargs: (int, optional): The arguments to pass to the new syscall.

        Returns:
            SyscallHandler: The SyscallHandler object.
        """
        if set(kwargs) - SyscallHijacker.allowed_args:
            raise ValueError("Invalid keyword arguments in syscall hijack")

        if isinstance(original_syscall, str):
            original_syscall_number = resolve_syscall_number(self.arch, original_syscall)
        else:
            original_syscall_number = original_syscall

        new_syscall_number = (
            resolve_syscall_number(self.arch, new_syscall) if isinstance(new_syscall, str) else new_syscall
        )

        if new_syscall_number == -1:
            raise ValueError("Cannot hijack a syscall with the 'ALL' syscall.")

        if original_syscall_number == new_syscall_number:
            raise ValueError(
                "The original syscall and the new syscall must be different during hijacking.",
            )

        on_enter = SyscallHijacker().create_hijacker(
            new_syscall_number,
            **kwargs,
        )

        # Check if the syscall is already handled (by the user or by the pretty print handler)
        if original_syscall_number in self.handled_syscalls:
            handler = self.handled_syscalls[original_syscall_number]
            if handler.on_enter_user or handler.on_exit_user:
                liblog.warning(
                    f"Syscall {original_syscall_number} is already handled by a user-defined handler. Overriding it.",
                )
            handler.on_enter_user = on_enter
            handler.on_exit_user = None
            handler.recursive = recursive
            handler.enabled = True
        else:
            handler = SyscallHandler(
                original_syscall_number,
                on_enter,
                None,
                None,
                None,
                recursive,
            )

            link_to_internal_debugger(handler, self)

            if not self._is_in_background():
                # Go through the queue and wait for it to be done
                self.__polling_thread_command_queue.put(
                    (self.__threaded_handle_syscall, (handler,)),
                )
                self._join_and_check_status()
            else:
                # Let's do this ourselves and move on
                self.__threaded_handle_syscall(handler)

        return handler

    @change_state_function_process
    def gdb(
        self: InternalDebugger,
        migrate_breakpoints: bool = True,
        open_in_new_process: bool = True,
        blocking: bool = True,
    ) -> None:
        """Migrates the current debugging session to GDB.

        Args:
            migrate_breakpoints (bool): Whether to migrate over the breakpoints set in libdebug to GDB.
            open_in_new_process (bool): Whether to attempt to open GDB in a new process instead of the current one.
            blocking (bool): Whether to block the script until GDB is closed.
        """
        if self._gdb_resume_event:
            raise RuntimeError("Unexpected state while migrating to GDB.")

        # Create the command file
        command_file = self._craft_gdb_migration_file(migrate_breakpoints)

        if open_in_new_process and libcontext.terminal:
            lambda_fun = self._open_gdb_in_new_process(command_file)
        elif open_in_new_process:
            self._auto_detect_terminal()
            if not libcontext.terminal:
                liblog.warning(
                    "Cannot auto-detect terminal. Please configure the terminal in libcontext.terminal. Opening gdb in the current shell.",
                )
                lambda_fun = self._open_gdb_in_shell(command_file)
            else:
                lambda_fun = self._open_gdb_in_new_process(command_file)
        else:
            lambda_fun = self._open_gdb_in_shell(command_file)

        self._is_migrated_to_gdb = True
        self._gdb_resume_event = GdbResumeEvent(self, lambda_fun)

        if blocking:
            self.wait_for_gdb()

    def wait_for_gdb(self: InternalDebugger) -> None:
        """Waits for the GDB process to migrate back to libdebug."""
        if not self._is_migrated_to_gdb:
            raise RuntimeError("Process is not in GDB.")

        if not self._gdb_resume_event:
            raise RuntimeError("GDB resume event is not set.")

        # Wait for the GDB process to terminate
        self._gdb_resume_event.join()
        self._gdb_resume_event = None

    def _auto_detect_terminal(self: InternalDebugger) -> None:
        """Auto-detects the terminal."""
        try:
            process = Process(self.process_id)
            while process:
                pname = process.name().lower()
                if terminal_command := TerminalTypes.get_command(pname):
                    libcontext.terminal = terminal_command
                    liblog.debugger(f"Auto-detected terminal: {libcontext.terminal}")
                process = process.parent()
        except Error:
            pass

    def _craft_gdb_migration_command(self: InternalDebugger, migrate_breakpoints: bool) -> str:
        """Crafts the command to migrate to GDB.

        Args:
            migrate_breakpoints (bool): Whether to migrate the breakpoints.

        Returns:
            str: The command to migrate to GDB.
        """
        gdb_command = f'gdb -q --pid {self.process_id} -ex "source {GDB_GOBACK_LOCATION} " -ex "ni" -ex "ni"'

        if not migrate_breakpoints:
            return gdb_command

        for bp in self.breakpoints.values():
            if bp.enabled:
                if bp.hardware and bp.condition == "rw":
                    gdb_command += f' -ex "awatch *(int{bp.length * 8}_t *) {bp.address:#x}"'
                elif bp.hardware and bp.condition == "w":
                    gdb_command += f' -ex "watch *(int{bp.length * 8}_t *) {bp.address:#x}"'
                elif bp.hardware:
                    gdb_command += f' -ex "hb *{bp.address:#x}"'
                else:
                    gdb_command += f' -ex "b *{bp.address:#x}"'

                if self.threads[0].instruction_pointer == bp.address and not bp.hardware:
                    # We have to enqueue an additional continue
                    gdb_command += ' -ex "ni"'

        return gdb_command

    def _craft_gdb_migration_file(self: InternalDebugger, migrate_breakpoints: bool) -> str:
        """Crafts the file to migrate to GDB.

        Args:
            migrate_breakpoints (bool): Whether to migrate the breakpoints.

        Returns:
            str: The path to the file.
        """
        # Different terminals accept what to run in different ways. To make this work with all terminals, we need to
        # create a temporary script that will run the command. This script will be executed by the terminal.
        command = self._craft_gdb_migration_command(migrate_breakpoints)
        with NamedTemporaryFile(delete=False, mode="w", suffix=".sh") as temp_file:
            temp_file.write("#!/bin/sh\n")
            temp_file.write(command)
            script_path = temp_file.name

        # Make the script executable
        Path.chmod(Path(script_path), 0o755)
        return script_path

    def _open_gdb_in_new_process(self: InternalDebugger, script_path: str) -> None:
        """Opens GDB in a new process following the configuration in libcontext.terminal.

        Args:
            script_path (str): The path to the script to run in the terminal.
        """
        # Check if the terminal has been configured correctly
        try:
            check_call([*libcontext.terminal, "uname"], stderr=DEVNULL, stdout=DEVNULL)
        except (CalledProcessError, FileNotFoundError) as err:
            raise RuntimeError(
                "Failed to open GDB in terminal. Check the terminal configuration in libcontext.terminal.",
            ) from err

        if not self._is_in_background():
            self.__polling_thread_command_queue.put((self.__threaded_gdb, ()))
            self._join_and_check_status()
        else:
            self.__threaded_gdb()

        # Create the command to open the terminal and run the script
        command = [*libcontext.terminal, script_path]

        # Open GDB in a new terminal
        terminal_pid = Popen(command).pid

        # This is the command line that we are looking for
        cmdline_target = ["/bin/sh", script_path]

        self._wait_for_gdb(terminal_pid, cmdline_target)

        def wait_for_termination() -> None:
            liblog.debugger("Waiting for GDB process to terminate...")

            for proc in process_iter():
                try:
                    cmdline = proc.cmdline()
                except ZombieProcess:
                    # This is a zombie process, which psutil tracks but we cannot interact with
                    continue

                if cmdline_target == cmdline:
                    gdb_process = proc
                    break
            else:
                raise RuntimeError("GDB process not found.")

            while gdb_process.is_running() and gdb_process.status() != STATUS_ZOMBIE:
                # As the GDB process is in a different group, we do not have the authority to wait on it
                # So we must keep polling it until it is no longer running
                pass

        return wait_for_termination

    def _open_gdb_in_shell(self: InternalDebugger, script_path: str) -> None:
        """Open GDB in the current shell.

        Args:
            script_path (str): The path to the script to run in the terminal.
        """
        self.__polling_thread_command_queue.put((self.__threaded_gdb, ()))
        self._join_and_check_status()

        gdb_pid = os.fork()

        if gdb_pid == 0:  # This is the child process.
            os.execv("/bin/sh", ["/bin/sh", script_path])
            raise RuntimeError("Failed to execute GDB.")

        # This is the parent process.
        # Parent ignores SIGINT, so only GDB (child) receives it
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        def wait_for_termination() -> None:
            # Wait for the child process to finish
            os.waitpid(gdb_pid, 0)

            # Reset the SIGINT behavior to default handling after child exits
            signal.signal(signal.SIGINT, signal.SIG_DFL)

        return wait_for_termination

    def _wait_for_gdb(self: InternalDebugger, terminal_pid: int, cmdline_target: list[str]) -> None:
        """Waits for GDB to open in the terminal.

        Args:
            terminal_pid (int): The PID of the terminal process.
            cmdline_target (list[str]): The command line that we are looking for.
        """
        # We need to wait for GDB to open in the terminal. However, different terminals have different behaviors
        # so we need to manually check if the terminal is still alive and if GDB has opened
        waiting_for_gdb = True
        terminal_alive = False
        scan_after_terminal_death = 0
        scan_after_terminal_death_max = 3
        while waiting_for_gdb:
            terminal_alive = False
            for proc in process_iter():
                try:
                    cmdline = proc.cmdline()
                    if cmdline == cmdline_target:
                        waiting_for_gdb = False
                    elif proc.pid == terminal_pid:
                        terminal_alive = True
                except ZombieProcess:
                    # This is a zombie process, which psutil tracks but we cannot interact with
                    continue
            if not terminal_alive and waiting_for_gdb and scan_after_terminal_death < scan_after_terminal_death_max:
                # If the terminal has died, we need to wait a bit before we can be sure that GDB will not open.
                # Indeed, some terminals take different steps to open GDB. We must be sure to refresh the list
                # of processes. One extra iteration should be enough, but we will iterate more just to be sure.
                scan_after_terminal_death += 1
            elif not terminal_alive and waiting_for_gdb:
                # If the terminal has died and GDB has not opened, we are sure that GDB will not open
                raise RuntimeError("Failed to open GDB in terminal.")

    def _resume_from_gdb(self: InternalDebugger) -> None:
        """Resumes the process after migrating from GDB."""
        if not self._is_in_background():
            self.__polling_thread_command_queue.put((self.__threaded_migrate_from_gdb, ()))
            self._join_and_check_status()
        else:
            self.__threaded_migrate_from_gdb()

        self._is_migrated_to_gdb = False

    @change_state_function_thread
    def step(self: InternalDebugger, thread: ThreadContext) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext): The thread to step. Defaults to None.
        """
        if not self._is_in_background():
            self.__polling_thread_command_queue.put((self.__threaded_step, (thread,)))
            self.__polling_thread_command_queue.put((self.__threaded_wait, ()))
            self._join_and_check_status()
        else:
            # Let's do this ourselves and move on
            self.__threaded_step(thread)
            self.__threaded_wait()

            # At this point, we need to continue the execution of the callback from which the step was called
            self.resume_context.resume = True

    @change_state_function_thread
    def step_until(
        self: InternalDebugger,
        thread: ThreadContext,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            thread (ThreadContext): The thread to step. Defaults to None.
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)

        if not self._is_in_background():
            self.__polling_thread_command_queue.put(
                (
                    self.__threaded_step_until,
                    (thread, address, max_steps),
                ),
            )
            self._join_and_check_status()
            self.set_stopped()
        else:
            self.__threaded_step_until(thread, address, max_steps)

            # At this point, we need to continue the execution of the callback from which the step_until was called
            self.resume_context.resume = True

    @change_state_function_thread
    def finish(self: InternalDebugger, thread: ThreadContext, heuristic: str = "backtrace") -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            thread (ThreadContext): The thread to finish.
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        if not self._is_in_background():
            self.__polling_thread_command_queue.put(
                (self.__threaded_finish, (thread, heuristic)),
            )
            self._join_and_check_status()
            self.set_stopped()
        else:
            self.__threaded_finish(thread, heuristic)

            # At this point, we need to continue the execution of the callback from which the finish was called
            self.resume_context.resume = True

    @change_state_function_thread
    def next(self: InternalDebugger, thread: ThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        if not self._is_in_background():
            self.__polling_thread_command_queue.put((self.__threaded_next, (thread,)))
            self._join_and_check_status()
            self.set_stopped()
        else:
            self.__threaded_next(thread)

            # At this point, we need to continue the execution of the callback from which the next was called
            self.resume_context.resume = True

    def enable_pretty_print(
        self: InternalDebugger,
    ) -> SyscallHandler:
        """Handles a syscall in the target process to pretty prints its arguments and return value."""
        self._ensure_process_stopped()

        syscall_numbers = get_all_syscall_numbers(self.arch)

        for syscall_number in syscall_numbers:
            # Check if the syscall is already handled (by the user or by the pretty print handler)
            if syscall_number in self.handled_syscalls:
                handler = self.handled_syscalls[syscall_number]
                if syscall_number not in (self.syscalls_to_not_pprint or []) and syscall_number in (
                    self.syscalls_to_pprint or syscall_numbers
                ):
                    handler.on_enter_pprint = pprint_on_enter
                    handler.on_exit_pprint = pprint_on_exit
                else:
                    # Remove the pretty print handler from previous pretty print calls
                    handler.on_enter_pprint = None
                    handler.on_exit_pprint = None
            elif syscall_number not in (self.syscalls_to_not_pprint or []) and syscall_number in (
                self.syscalls_to_pprint or syscall_numbers
            ):
                handler = SyscallHandler(
                    syscall_number,
                    None,
                    None,
                    pprint_on_enter,
                    pprint_on_exit,
                )

                link_to_internal_debugger(handler, self)

                # We have to disable the handler since it is not user-defined
                handler.disable()

                self.__polling_thread_command_queue.put(
                    (self.__threaded_handle_syscall, (handler,)),
                )

        self._join_and_check_status()

    def disable_pretty_print(self: InternalDebugger) -> None:
        """Disable the handler for all the syscalls that are pretty printed."""
        self._ensure_process_stopped()

        installed_handlers = list(self.handled_syscalls.values())
        for handler in installed_handlers:
            if handler.on_enter_pprint or handler.on_exit_pprint:
                if handler.on_enter_user or handler.on_exit_user:
                    handler.on_enter_pprint = None
                    handler.on_exit_pprint = None
                else:
                    self.__polling_thread_command_queue.put(
                        (self.__threaded_unhandle_syscall, (handler,)),
                    )

        self._join_and_check_status()

    def insert_new_thread(self: InternalDebugger, thread: ThreadContext) -> None:
        """Insert a new thread in the context.

        Args:
            thread (ThreadContext): the thread to insert.
        """
        if thread in self.threads:
            raise RuntimeError("Thread already registered.")

        self.threads.append(thread)

    def set_thread_as_dead(
        self: InternalDebugger,
        thread_id: int,
        exit_code: int | None,
        exit_signal: int | None,
    ) -> None:
        """Set a thread as dead and update its exit code and exit signal.

        Args:
            thread_id (int): the ID of the thread to set as dead.
            exit_code (int, optional): the exit code of the thread.
            exit_signal (int, optional): the exit signal of the thread.
        """
        for thread in self.threads:
            if thread.thread_id == thread_id:
                thread.set_as_dead()
                thread._exit_code = exit_code
                thread._exit_signal = exit_signal
                break

        if self.threads[0].dead:
            self.notify_timeout_thread_debuggee_died()

    def set_all_threads_as_dead(self: InternalDebugger) -> None:
        """Set all threads as dead."""
        for thread in self.threads:
            thread.set_as_dead()

        self.notify_timeout_thread_debuggee_died()

    def get_thread_by_id(self: InternalDebugger, thread_id: int) -> ThreadContext:
        """Get a thread by its ID.

        Args:
            thread_id (int): the ID of the thread to get.

        Returns:
            ThreadContext: the thread with the specified ID.
        """
        for thread in self.threads:
            if thread.thread_id == thread_id and not thread.dead:
                return thread

        return None

    def resolve_address(
        self: InternalDebugger,
        address: int,
        backing_file: str,
        skip_absolute_address_validation: bool = False,
    ) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.
            backing_file (str): The backing file to resolve the address in.
            skip_absolute_address_validation (bool, optional): Whether to skip bounds checking for absolute addresses. Defaults to False.

        Returns:
            int: The normalized and validated address.

        Raises:
            ValueError: If the substring `backing_file` is present in multiple backing files.
        """
        if skip_absolute_address_validation and backing_file == "absolute":
            return address

        maps = self.maps

        if backing_file in ["hybrid", "absolute"]:
            if maps.filter(address):
                # If the address is absolute, we can return it directly
                return address
            elif backing_file == "absolute":
                # The address is explicitly an absolute address but we did not find it
                raise ValueError(
                    "The specified absolute address does not exist. Check the address or specify a backing file.",
                )
            else:
                # If the address was not found and the backing file is not "absolute",
                # we have to assume it is in the main map
                backing_file = self._process_full_path
                liblog.warning(
                    f"No backing file specified and no corresponding absolute address found for {hex(address)}. Assuming `{backing_file}`.",
                )

        filtered_maps = maps.filter(backing_file)

        return normalize_and_validate_address(address, filtered_maps)

    @change_state_function_process
    def resolve_symbol(self: InternalDebugger, symbol: str, backing_file: str) -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.
            backing_file (str): The backing file to resolve the symbol in.

        Returns:
            int: The address of the symbol.
        """
        if backing_file == "absolute":
            raise ValueError("Cannot use `absolute` backing file with symbols.")

        if backing_file == "hybrid":
            # If no explicit backing file is specified, we try resolving the symbol in the main map
            filtered_maps = self.maps.filter("binary")
            try:
                with extend_internal_debugger(self):
                    return resolve_symbol_in_maps(symbol, filtered_maps)
            except ValueError:
                liblog.warning(
                    f"No backing file specified for the symbol `{symbol}`. Resolving the symbol in ALL the maps (slow!)",
                )

            # Otherwise, we resolve the symbol in all the maps: as this can be slow,
            # we issue a warning with the file containing it
            maps = self.maps
            with extend_internal_debugger(self):
                address = resolve_symbol_in_maps(symbol, maps)

            filtered_maps = self.maps.filter(address)
            if len(filtered_maps) != 1:
                # Shouldn't happen, but you never know...
                raise RuntimeError(
                    "The symbol address is present in zero or multiple backing files. Please specify the correct backing file.",
                )
            liblog.warning(
                f"Symbol `{symbol}` found in `{filtered_maps[0].backing_file}`, "
                f"specify it manually as the backing file for better performance.",
            )

            return address

        if backing_file in ["binary", self._process_name]:
            backing_file = self._process_full_path

        filtered_maps = self.maps.filter(backing_file)

        with extend_internal_debugger(self):
            return resolve_symbol_in_maps(symbol, filtered_maps)

    @property
    def symbols(self: InternalDebugger) -> SymbolList[Symbol]:
        """Get the symbols of the process."""
        backing_files = {vmap.backing_file for vmap in self.maps}
        with extend_internal_debugger(self):
            return get_all_symbols(backing_files)

    def _background_ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        # There is no case where this should ever happen, but...
        if self._is_migrated_to_gdb:
            raise RuntimeError("Cannot execute this command after migrating to GDB.")

    @background_alias(_background_ensure_process_stopped)
    def _ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        if self._is_migrated_to_gdb:
            raise RuntimeError("Cannot execute this command after migrating to GDB.")

        if not self.running:
            return

        if self.auto_interrupt_on_command and not self.threads[0].zombie:
            self.interrupt()

        self._join_and_check_status()

    @background_alias(_background_ensure_process_stopped)
    def _ensure_process_stopped_regs(self: InternalDebugger) -> None:
        """Validates the state of the process. This is designed to be used by register-related commands."""
        if self._is_migrated_to_gdb:
            raise RuntimeError("Cannot execute this command after migrating to GDB.")

        if not self.is_debugging and not self.threads[0].dead:
            # The process is not being debugged, we cannot access registers
            # We can still access registers if the process is dead to guarantee post-mortem analysis
            raise RuntimeError("The process is not being debugged, cannot access registers. Check your script.")

        if not self.running:
            return

        if self.auto_interrupt_on_command and not self.threads[0].zombie:
            self.interrupt()

        self._join_and_check_status()

    def _is_in_background(self: InternalDebugger) -> None:
        return current_thread() == self.__polling_thread

    def __polling_thread_function(self: InternalDebugger) -> None:
        """This function is run in a thread. It is used to poll the process for state change."""
        while True:
            # Wait for the main thread to signal a command to execute
            command, args = self.__polling_thread_command_queue.get()

            if command == THREAD_TERMINATE:
                # Signal that the command has been executed
                self.__polling_thread_command_queue.task_done()
                return

            # Execute the command
            try:
                return_value = command(*args)
            except BaseException as e:  # noqa: BLE001
                raise_exception_to_main_thread(e)
                return_value = None

            if return_value is not None:
                self.__polling_thread_response_queue.put(return_value)

            # Signal that the command has been executed
            self.__polling_thread_command_queue.task_done()

            if return_value is not None:
                self.__polling_thread_response_queue.join()

    def _check_status(self: InternalDebugger) -> None:
        """Check for any exceptions raised by the background thread."""
        if not self.__polling_thread_response_queue.empty():
            response = self.__polling_thread_response_queue.get()
            self.__polling_thread_response_queue.task_done()
            if response is not None:
                raise response

    def _join_and_check_status(self: InternalDebugger) -> None:
        """Wait for the background thread to signal "task done" before returning."""
        # We don't want any asynchronous behaviour here
        self.__polling_thread_command_queue.join()
        self._check_status()

    @functools.cached_property
    def _process_full_path(self: InternalDebugger) -> str:
        """Get the full path of the process.

        Returns:
            str: the full path of the process.
        """
        return str(Path(f"/proc/{self.process_id}/exe").readlink())

    @functools.cached_property
    def _process_name(self: InternalDebugger) -> str:
        """Get the name of the process.

        Returns:
            str: the name of the process.
        """
        with Path(f"/proc/{self.process_id}/comm").open() as f:
            return f.read().strip()

    def __threaded_run(self: InternalDebugger, redirect_pipes: bool) -> None:
        liblog.debugger("Starting process %s.", self.path)
        self.debugging_interface.run(redirect_pipes)

        self.set_stopped()

    def __threaded_attach(self: InternalDebugger, pid: int) -> None:
        liblog.debugger("Attaching to process %d.", pid)
        self.debugging_interface.attach(pid)

        self.set_stopped()

    def __threaded_detach(self: InternalDebugger) -> None:
        liblog.debugger("Detaching from process %d.", self.process_id)
        self.debugging_interface.detach()

        self.set_stopped()

    def __threaded_kill(self: InternalDebugger) -> None:
        if self.argv:
            liblog.debugger(
                "Killing process %s (%d).",
                self.path,
                self.process_id,
            )
        else:
            liblog.debugger("Killing process %d.", self.process_id)
        self.debugging_interface.kill()

    def __threaded_cont(self: InternalDebugger) -> None:
        if self.argv:
            liblog.debugger(
                "Continuing process %s (%d).",
                self.path,
                self.process_id,
            )
        else:
            liblog.debugger("Continuing process %d.", self.process_id)

        self.set_running()
        self.debugging_interface.cont()

    def __threaded_wait(self: InternalDebugger) -> None:
        if self.argv:
            liblog.debugger(
                "Waiting for process %s (%d) to stop.",
                self.path,
                self.process_id,
            )
        else:
            liblog.debugger("Waiting for process %d to stop.", self.process_id)

        while True:
            if self.threads[0].dead:
                # All threads are dead
                liblog.debugger("All threads dead")
                break
            self.resume_context.resume = True

            self.debugging_interface.wait()

            if self.resume_context.resume:
                self.debugging_interface.cont()
            else:
                break

        self.set_stopped()

    def __threaded_breakpoint(self: InternalDebugger, bp: Breakpoint) -> None:
        liblog.debugger("Setting breakpoint at 0x%x.", bp.address)
        self.debugging_interface.set_breakpoint(bp)

    def __threaded_catch_signal(self: InternalDebugger, catcher: SignalCatcher) -> None:
        liblog.debugger(
            f"Setting the catcher for signal {resolve_signal_name(catcher.signal_number)} ({catcher.signal_number}).",
        )
        self.debugging_interface.set_signal_catcher(catcher)

    def __threaded_handle_syscall(self: InternalDebugger, handler: SyscallHandler) -> None:
        liblog.debugger(f"Setting the handler for syscall {handler.syscall_number}.")
        self.debugging_interface.set_syscall_handler(handler)

    def __threaded_unhandle_syscall(self: InternalDebugger, handler: SyscallHandler) -> None:
        liblog.debugger(f"Unsetting the handler for syscall {handler.syscall_number}.")
        self.debugging_interface.unset_syscall_handler(handler)

    def __threaded_step(self: InternalDebugger, thread: ThreadContext) -> None:
        liblog.debugger("Stepping thread %s.", thread.thread_id)
        self.debugging_interface.step(thread)

    def __threaded_step_until(
        self: InternalDebugger,
        thread: ThreadContext,
        address: int,
        max_steps: int,
    ) -> None:
        liblog.debugger("Stepping thread %s until 0x%x.", thread.thread_id, address)
        self.debugging_interface.step_until(thread, address, max_steps)

    def __threaded_finish(self: InternalDebugger, thread: ThreadContext, heuristic: str) -> None:
        prefix = heuristic.capitalize()
        liblog.debugger(f"{prefix} finish on thread %s", thread.thread_id)
        self.debugging_interface.finish(thread, heuristic=heuristic)

    def __threaded_next(self: InternalDebugger, thread: ThreadContext) -> None:
        liblog.debugger("Next on thread %s.", thread.thread_id)
        self.debugging_interface.next(thread)

    def __threaded_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_to_gdb()

    def __threaded_migrate_from_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_from_gdb()

    def __threaded_peek_memory(self: InternalDebugger, address: int) -> bytes | Exception:
        try:
            value = self.debugging_interface.peek_memory(address)
            result = value.to_bytes(get_platform_gp_register_size(libcontext.platform), sys.byteorder)
        except Exception as e:  # noqa:BLE001
            result = e
        return result

    def __threaded_poke_memory(self: InternalDebugger, address: int, data: bytes) -> None | Exception:
        int_data = int.from_bytes(data, sys.byteorder)
        try:
            self.debugging_interface.poke_memory(address, int_data)
        except Exception as e:
            return e

    def __threaded_fetch_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        self.debugging_interface.fetch_fp_registers(registers)

    def __threaded_flush_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        self.debugging_interface.flush_fp_registers(registers)

    @background_alias(__threaded_peek_memory)
    def _peek_memory(self: InternalDebugger, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before reading memory.",
            )

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_peek_memory, (address,)),
        )

        # We cannot call _join_and_check_status here, as we need the return value which might not be an exception
        self.__polling_thread_command_queue.join()

        value = self.__polling_thread_response_queue.get()
        self.__polling_thread_response_queue.task_done()

        if isinstance(value, BaseException):
            raise value

        return value

    def _fast_read_memory(self: InternalDebugger, address: int, size: int) -> bytes:
        """Reads memory from the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before reading memory.",
            )

        self._ensure_process_stopped()

        return self._process_memory_manager.read(address, size)

    @background_alias(__threaded_poke_memory)
    def _poke_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before writing to memory.",
            )

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_poke_memory, (address, data)),
        )

        self._join_and_check_status()

    def _fast_write_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before writing to memory.",
            )

        self._ensure_process_stopped()

        self._process_memory_manager.write(address, data)

    @background_alias(__threaded_fetch_fp_registers)
    def _fetch_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        """Fetches the floating point registers of a thread."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot read floating-point registers.")

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_fetch_fp_registers, (registers,)),
        )

        self._join_and_check_status()

    @background_alias(__threaded_flush_fp_registers)
    def _flush_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        """Flushes the floating point registers of a thread."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot write floating-point registers.")

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_flush_fp_registers, (registers,)),
        )

        self._join_and_check_status()

    def _enable_antidebug_escaping(self: InternalDebugger) -> None:
        """Enables the anti-debugging escape mechanism."""
        handler = SyscallHandler(
            resolve_syscall_number(self.arch, "ptrace"),
            on_enter_ptrace,
            on_exit_ptrace,
            None,
            None,
        )

        link_to_internal_debugger(handler, self)

        self.__polling_thread_command_queue.put((self.__threaded_handle_syscall, (handler,)))

        self._join_and_check_status()

        # Seutp hidden state for the handler
        handler._traceme_called = False
        handler._command = None

    @property
    def running(self: InternalDebugger) -> bool:
        """Get the state of the process.

        Returns:
            bool: True if the process is running, False otherwise.
        """
        return self._is_running

    def set_running(self: InternalDebugger) -> None:
        """Set the state of the process to running."""
        self._is_running = True

    def set_stopped(self: InternalDebugger) -> None:
        """Set the state of the process to stopped."""
        self._is_running = False

    @change_state_function_process
    def create_snapshot(self: Debugger, level: str = "base", name: str | None = None) -> ProcessSnapshot:
        """Create a snapshot of the current process state.

        Snapshot levels:
        - base: Registers
        - writable: Registers, writable memory contents
        - full: Registers, all memory contents

        Args:
            level (str): The level of the snapshot.
            name (str, optional): The name of the snapshot. Defaults to None.

        Returns:
            ProcessSnapshot: The created snapshot.
        """
        self._ensure_process_stopped()
        return ProcessSnapshot(self, level, name)

    def load_snapshot(self: Debugger, file_path: str) -> Snapshot:
        """Load a snapshot of the thread / process state.

        Args:
            file_path (str): The path to the snapshot file.
        """
        loaded_snap = self.serialization_helper.load(file_path)

        # Log the creation of the snapshot
        named_addition = " named " + loaded_snap.name if loaded_snap.name is not None else ""
        liblog.debugger(
            f"Loaded {type(loaded_snap)} snapshot {loaded_snap.snapshot_id} of level {loaded_snap.level} from file {file_path}{named_addition}"
        )

        return loaded_snap

    def notify_snaphot_taken(self: InternalDebugger) -> None:
        """Notify the debugger that a snapshot has been taken."""
        self._snapshot_count += 1

    def lazily_inflate_timeout_thread(self: InternalDebugger) -> None:
        """Inflates the timeout thread and all the linked objects, if needed."""
        # Check if the timeout thread is already inflated
        if self.__timeout_thread is None:
            # Inflate the command queue
            self.__timeout_thread_command_queue = Queue()

            # Inflate the conditional variable
            self.__timeout_thread_conditional = Event()

            # Inflate the timeout thread
            self.__timeout_thread = Thread(
                name="libdebug__timeout_thread",
                target=self.__timeout_thread_function,
                daemon=True,
            )
            self.__timeout_thread.start()
            liblog.debugger("Timeout thread created.")

    def enqueue_timeout_command(self: InternalDebugger, timeout: float) -> None:
        """Enqueue a timeout command to the timeout thread."""
        self.lazily_inflate_timeout_thread()

        # Ensure that the command queue is empty
        if not self.__timeout_thread_command_queue.empty():
            raise RuntimeError("Timeout thread command queue is not empty.")

        # Unset the conditional variable
        self.__timeout_thread_conditional.clear()

        # Enqueue the timeout
        self.__timeout_thread_command_queue.put(timeout)

        liblog.debugger(
            "Timeout thread command enqueued. Timeout set to %f seconds.",
            timeout,
        )

    def notify_timeout_thread_debuggee_died(self: InternalDebugger) -> None:
        """If the timeout thread is active, we must let it know that the debuggee died."""
        if self.__timeout_thread is not None:
            # Notify the timeout thread that the debuggee died
            self.__timeout_thread_conditional.set()

            # Check that the timeout thread has signaled "task done"
            self.__timeout_thread_command_queue.join()

    def cleanup_timeout_thread(self: InternalDebugger) -> None:
        """Cleans up the timeout thread and all the linked objects."""
        if self.__timeout_thread is not None:
            # Notify the timeout thread to terminate
            self.__timeout_thread_command_queue.put(THREAD_TERMINATE)

            # Wait for the timeout thread to terminate
            self.__timeout_thread.join()

            # Cleanup the command queue
            self.__timeout_thread_command_queue = None

            # Cleanup the conditional variable
            self.__timeout_thread_conditional = None

            # Cleanup the timeout thread
            self.__timeout_thread = None

            liblog.debugger("Timeout thread cleaned up.")

    def __timeout_thread_function(self: InternalDebugger) -> None:
        """This function continously checks for timeouts and kills the debuggee if needed."""
        while True:
            # Wait for the main thread to signal a command to execute
            timeout_amount = self.__timeout_thread_command_queue.get()

            if timeout_amount == THREAD_TERMINATE:
                # Signal that the command has been executed
                self.__timeout_thread_command_queue.task_done()
                return

            debuggee_died = self.__timeout_thread_conditional.wait(timeout_amount)

            if not debuggee_died:
                # This is racy, but the side-effect is us printing a warning
                # and not much else
                if self.resume_context.is_in_callback:
                    # We have no way to stop the callback, let's notify the user
                    liblog.warning(
                        "Timeout occurred while executing a callback. Asynchronous callbacks cannot be interrupted.",
                    )

                # Kill it
                try:
                    os.kill(self.process_id, signal.SIGKILL)
                    liblog.debugger(
                        "Debuggee process %s (%d) killed due to timeout.",
                        self.path,
                        self.process_id,
                    )
                except ProcessLookupError:
                    liblog.debugger(
                        "Debuggee process %s (%d) already dead.",
                        self.path,
                        self.process_id,
                    )
                except Exception as e:  # noqa: BLE001
                    liblog.debugger(
                        "Error while killing timed out debuggee process %s (%d): %s",
                        self.path,
                        self.process_id,
                        e,
                    )

                # We manually stop the background wait-cont loop, just to make sure
                self.resume_context.resume = False

                # Wait for the main thread to notice it has died
                self.__timeout_thread_conditional.wait()

            # Signal that the command has been executed
            self.__timeout_thread_command_queue.task_done()

    def clear_all_caches(self: InternalDebugger) -> None:
        """Clears all the caches of the internal debugger."""
        # The cached properties can be cleared by deleting the attribute
        if "_process_full_path" in self.__dict__:
            del self._process_full_path

        if "_process_name" in self.__dict__:
            del self._process_name
