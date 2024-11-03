#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
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
from subprocess import Popen
from tempfile import NamedTemporaryFile
from threading import Thread, current_thread
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
from libdebug.debugger.internal_debugger_instance_manager import (
    extend_internal_debugger,
    link_to_internal_debugger,
)
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.memory.chunked_memory_view import ChunkedMemoryView
from libdebug.memory.direct_memory_view import DirectMemoryView
from libdebug.memory.process_memory_manager import ProcessMemoryManager
from libdebug.state.resume_context import ResumeContext
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.arch_mappings import map_arch
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
from libdebug.utils.libcontext import libcontext
from libdebug.utils.platform_utils import get_platform_register_size
from libdebug.utils.signal_utils import (
    resolve_signal_name,
    resolve_signal_number,
)
from libdebug.utils.syscall_utils import (
    get_all_syscall_numbers,
    resolve_syscall_name,
    resolve_syscall_number,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from libdebug.commlink.pipe_manager import PipeManager
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.data.registers import Registers
    from libdebug.data.symbol import Symbol
    from libdebug.data.symbol_list import SymbolList
    from libdebug.debugger import Debugger
    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.memory.abstract_memory_view import AbstractMemoryView
    from libdebug.state.internal_thread_context import InternalThreadContext

THREAD_TERMINATE = -1
GDB_GOBACK_LOCATION = str((Path(__file__).parent.parent / "utils" / "gdb.py").resolve())


class InternalDebugger:
    """A class that holds the global debugging state."""

    aslr_enabled: bool
    """A flag that indicates if ASLR is enabled or not."""

    arch: str
    """The architecture of the debugged process."""

    argv: list[str]
    """The command line arguments of the debugged process."""

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

    internal_threads: list[InternalThreadContext]
    """A list of all the internal thread contexts of the debugged process."""

    public_threads: list[ThreadContext]
    """A list of all the public thread contexts of the debugged process."""

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

    _is_migrated_to_gdb: bool
    """A flag that indicates if the debuggee was migrated to GDB."""

    _fast_memory: DirectMemoryView
    """The memory view of the debugged process using the fast memory access method."""

    _slow_memory: ChunkedMemoryView
    """The memory view of the debugged process using the slow memory access method."""

    def __init__(self: InternalDebugger) -> None:
        """Initialize the context."""
        # These must be reinitialized on every call to "debugger"
        self.aslr_enabled = False
        self.autoreach_entrypoint = True
        self.argv = []
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
        self.internal_threads = []
        self.public_threads = []
        self.instanced = False
        self.is_debugging = False
        self._is_migrated_to_gdb = False
        self.resume_context = ResumeContext()
        self.stdin_settings_backup = []
        self.arch = map_arch(libcontext.platform)
        self.kill_on_exit = True
        self._process_memory_manager = ProcessMemoryManager()
        self.fast_memory = False
        self.__polling_thread_command_queue = Queue()
        self.__polling_thread_response_queue = Queue()

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

        for t in self.internal_threads:
            del t.regs.register_file
            del t.regs._fp_register_file

        self.internal_threads.clear()
        self.public_threads.clear()
        self.instanced = False
        self.is_debugging = False
        self.resume_context.clear()

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
                unit_size=get_platform_register_size(libcontext.platform),
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

    def run(self: InternalDebugger, redirect_pipes: bool = True) -> PipeManager | None:
        """Starts the process and waits for it to stop.

        Args:
            redirect_pipes (bool): Whether to hook and redirect the pipes of the process to a PipeManager.
        """
        if not self.argv:
            raise RuntimeError("No binary file specified.")

        if not Path(self.argv[0]).is_file():
            raise RuntimeError(f"File {self.argv[0]} does not exist.")

        if not os.access(self.argv[0], os.X_OK):
            raise RuntimeError(
                f"File {self.argv[0]} is not executable.",
            )

        if self.is_debugging:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.internal_threads:
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

        if redirect_pipes and not self.pipe_manager:
            raise RuntimeError("Something went wrong during pipe initialization.")

        self._process_memory_manager.open(self.process_id)

        return self.pipe_manager

    def attach(self: InternalDebugger, pid: int) -> None:
        """Attaches to an existing process."""
        if self.is_debugging:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.internal_threads:
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

        self.ensure_process_stopped()

        self.__polling_thread_command_queue.put((self.__threaded_detach, ()))

        self.is_debugging = False

        self._join_and_check_status()

        self._process_memory_manager.close()

    @background_alias(_background_invalid_call)
    def kill(self: InternalDebugger) -> None:
        """Kills the process."""
        if not self.is_debugging:
            raise RuntimeError("No process currently debugged, cannot kill.")
        try:
            self.ensure_process_stopped()
        except (OSError, RuntimeError):
            # This exception might occur if the process has already died
            liblog.debugger("OSError raised during kill")

        self._process_memory_manager.close()

        self.__polling_thread_command_queue.put((self.__threaded_kill, ()))

        self.instanced = False
        self.is_debugging = False

        if self.pipe_manager:
            self.pipe_manager.close()

        self._join_and_check_status()

    def terminate(self: InternalDebugger) -> None:
        """Interrupts the process, kills it and then terminates the background thread.

        The debugger object will not be usable after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        if self.instanced and self.any_thread_running:
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

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def cont(self: InternalDebugger, thread: InternalThreadContext = None) -> None:
        """Continues the process.

        Args:
            auto_wait (bool, optional): Whether to automatically wait for the process to stop after continuing. Defaults to True.
            thread (InternalThreadContext, optional): The thread to continue. Defaults to None.
        """
        self.__polling_thread_command_queue.put((self.__threaded_cont, (thread,)))

        self._join_and_check_status()

        self.__polling_thread_command_queue.put((self.__threaded_wait, (thread,)))

    @background_alias(_background_invalid_call)
    def interrupt(self: InternalDebugger, thread: InternalThreadContext = None) -> None:
        """Interrupts the process or a specific thread.

        Args:
            thread (InternalThreadContext, optional): The thread to interrupt. Defaults to None.
        """
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot interrupt.")

        # We have to ensure that at least one thread is alive before executing the method
        if self.internal_threads[0].dead:
            raise RuntimeError("All threads are dead.")

        if thread is not None and thread.dead:
            raise RuntimeError("The thread is dead.")

        if thread is None:
            if not self.any_thread_running:
                return

            self.resume_context.force_interrupt = True
            os.kill(self.process_id, SIGSTOP)

            self.wait()
        else:
            if not thread.running:
                return

            self.resume_context.force_interrupt = True

            # The thread will not be scheduled anymore
            thread.scheduled = False

            # Stop the entire process to avoid inconsistencies
            os.kill(self.process_id, SIGSTOP)

            # At this point all threads should be stopped and with the running flag set to False
            self.wait()

            # Get the scheduled threads
            scheduled_threads = [t for t in self.internal_threads if t.scheduled]

            # Resume the threads we do not want to interrupt
            for t in scheduled_threads:
                self.__polling_thread_command_queue.put((self.__threaded_cont, (t,)))
                self._join_and_check_status()

            # We need to push a wait in the background thread to ensure that the running threads are correcyly managed
            self.__polling_thread_command_queue.put((self.__threaded_wait, ()))

    @background_alias(_background_invalid_call)
    def wait(self: InternalDebugger, thread: InternalThreadContext = None) -> None:
        """Waits for the process or a specific thread to stop.

        Args:
            thread (InternalThreadContext, optional): The thread to wait for. Defaults to None.
        """
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot wait.")

        self._join_and_check_status()

        if (
            self.internal_threads[0].dead
            or not self.any_thread_running
            or thread is not None
            and (thread.dead or not thread.running)
        ):
            # Most of the time the function returns here, as there was a wait already
            # queued by the previous command
            return

        self.__polling_thread_command_queue.put((self.__threaded_wait, (thread,)))

        self._join_and_check_status()

    @property
    def maps(self: InternalDebugger) -> MemoryMapList[MemoryMap]:
        """Returns the memory maps of the process."""
        self.ensure_process_stopped()
        return self.debugging_interface.get_maps()

    @property
    def memory(self: InternalDebugger) -> AbstractMemoryView:
        """The memory view of the debugged process."""
        return self._fast_memory if self.fast_memory else self._slow_memory

    def pprint_maps(self: InternalDebugger) -> None:
        """Prints the memory maps of the process."""
        self.ensure_process_stopped()
        header = (
            f"{'start':>18}  "
            f"{'end':>18}  "
            f"{'perm':>6}  "
            f"{'size':>8}  "
            f"{'offset':>8}  "
            f"{'backing_file':<20}"
        )
        print(header)
        for memory_map in self.maps:
            info = (
                f"{memory_map.start:#18x}  "
                f"{memory_map.end:#18x}  "
                f"{memory_map.permissions:>6}  "
                f"{memory_map.size:#8x}  "
                f"{memory_map.offset:#8x}  "
                f"{memory_map.backing_file}"
            )
            if "rwx" in memory_map.permissions:
                print(f"{ANSIColors.RED}{ANSIColors.UNDERLINE}{info}{ANSIColors.RESET}")
            elif "x" in memory_map.permissions:
                print(f"{ANSIColors.RED}{info}{ANSIColors.RESET}")
            elif "w" in memory_map.permissions:
                print(f"{ANSIColors.YELLOW}{info}{ANSIColors.RESET}")
            elif "r" in memory_map.permissions:
                print(f"{ANSIColors.GREEN}{info}{ANSIColors.RESET}")
            else:
                print(info)

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def breakpoint(
        self: InternalDebugger,
        position: int | str,
        hardware: bool = False,
        condition: str = "x",
        length: int = 1,
        callback: None | bool | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
        thread_id: int = -1,
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (None | bool | Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. If True, an empty callback will be set. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
            thread_id (int, optional): The thread ID of the thread for which the breakpoint should be set. Defaults to -1, which means all threads.
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

        if bp := self.breakpoints.get(address):
            # TODO: we should allow multiple breakpoints at the same address (e.g., for different threads)
            liblog.warning(f"Breakpoint at {position} already set. Overriding it.")

        bp = Breakpoint(address, position, thread_id, 0, hardware, callback, condition.lower(), length)

        if hardware:
            validate_hardware_breakpoint(self.arch, bp)

        link_to_internal_debugger(bp, self)

        self.__polling_thread_command_queue.put((self.__threaded_breakpoint, (bp, thread_id)))

        self._join_and_check_status()

        # the breakpoint should have been set by interface
        if address not in self.breakpoints:
            raise RuntimeError("Something went wrong while inserting the breakpoint.")

        return bp

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def catch_signal(
        self: InternalDebugger,
        signal: int | str,
        callback: None | bool | Callable[[ThreadContext, SignalCatcher], None] = None,
        recursive: bool = False,
        thread_id: int = -1,
    ) -> SignalCatcher:
        """Catch a signal in the target process.

        Args:
            signal (int | str): The signal to catch. If "*", "ALL", "all" or -1 is passed, all signals will be caught.
            callback (None | bool | Callable[[ThreadContext, SignalCatcher], None], optional): A callback to be called when the signal is caught. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.
            thread_id (int, optional): The thread ID of the thread for which the signal should be caught. Defaults to -1, which means all threads.

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
                raise ValueError(
                    f"Cannot catch SIGTRAP ({signal_number}) as it is used by the debugger or ptrace for their internal operations.",
                )

        if signal_number in self.caught_signals:
            # TODO: we should allow multiple catchers at the same signal (e.g., for different threads)
            liblog.warning(
                f"Signal {resolve_signal_name(signal_number)} ({signal_number}) has already been caught. Overriding it.",
            )

        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")

        if callback is True:

            def callback(_: ThreadContext, __: SignalCatcher) -> None:
                pass

        catcher = SignalCatcher(signal_number, thread_id, callback, recursive)

        link_to_internal_debugger(catcher, self)

        self.__polling_thread_command_queue.put((self.__threaded_catch_signal, (catcher,)))

        self._join_and_check_status()

        return catcher

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def hijack_signal(
        self: InternalDebugger,
        original_signal: int | str,
        new_signal: int | str,
        recursive: bool = False,
        thread_id: int = -1,
    ) -> SignalCatcher:
        """Hijack a signal in the target process.

        Args:
            original_signal (int | str): The signal to hijack. If "*", "ALL", "all" or -1 is passed, all signals will be hijacked.
            new_signal (int | str): The signal to hijack the original signal with.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.
            thread_id (int, optional): The thread ID of the thread for which the signal should be hijacked. Defaults to -1, which means all threads.

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

        return self.catch_signal(original_signal_number, callback, recursive, thread_id)

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def handle_syscall(
        self: InternalDebugger,
        syscall: int | str,
        on_enter: Callable[[ThreadContext, SyscallHandler], None] | None = None,
        on_exit: Callable[[ThreadContext, SyscallHandler], None] | None = None,
        recursive: bool = False,
        thread_id: int = -1,
    ) -> SyscallHandler:
        """Handle a syscall in the target process or the specified thread.

        Args:
            syscall (int | str): The syscall name or number to handle. If "*", "ALL", "all", or -1 is passed, all syscalls will be handled.
            on_enter (None | bool |Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is entered. If True, an empty callback will be set. Defaults to None.
            on_exit (None | bool | Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is exited. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.
            thread_id (int, optional): The thread ID of the thread for which the syscall should be handled. Defaults to -1, which means all threads.

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
                # TODO: we should allow multiple handlers at the same syscall (e.g., for different threads)
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, syscall_number)} is already handled by a user-defined "
                    "handler. Overriding it.",
                )
            if thread_id != -1 and (handler.on_enter_pprint or handler.on_exit_pprint):
                # TODO: we should remove this limitation ASAP
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, syscall_number)} is already handled by the pretty print "
                    "handler. The handler will be process scoped. This will be solved in future releases.",
                )
            elif thread_id != handler.thread_id:
                # TODO: we should allow multiple handlers at the same syscall (e.g., for different threads)
                handler.thread_id = thread_id
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, syscall_number)} is already handled by another thread. "
                    "Overriding it.",
                )

            handler.on_enter_user = on_enter
            handler.on_exit_user = on_exit
            handler.recursive = recursive
            handler.enabled = True
        else:
            handler = SyscallHandler(
                syscall_number,
                thread_id,
                on_enter,
                on_exit,
                None,
                None,
                recursive,
            )

            link_to_internal_debugger(handler, self)

            self.__polling_thread_command_queue.put(
                (self.__threaded_handle_syscall, (handler,)),
            )

            self._join_and_check_status()

        return handler

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def hijack_syscall(
        self: InternalDebugger,
        original_syscall: int | str,
        new_syscall: int | str,
        recursive: bool = True,
        thread_id: int = -1,
        **kwargs: int,
    ) -> SyscallHandler:
        """Hijacks a syscall in the target process or the specified thread.

        Args:
            original_syscall (int | str): The syscall name or number to hijack. If "*", "ALL", "all" or -1 is passed, all syscalls will be hijacked.
            new_syscall (int | str): The syscall name or number to hijack the original syscall with.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.
            thread_id (int, optional): The thread ID of the thread for which the syscall should be hijacked. Defaults to -1, which means all threads.
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
                # TODO: we should allow multiple handlers at the same syscall (e.g., for different threads)
                liblog.warning(
                    f"Syscall {original_syscall_number} is already handled by a user-defined handler. Overriding it. ",
                )
            if thread_id != -1 and (handler.on_enter_pprint or handler.on_exit_pprint):
                # TODO: we should remove this limitation ASAP
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, original_syscall_number)} is already handled by the "
                    "pretty print handler. The handler will be process scoped. This will be solved in future releases.",
                )
            elif thread_id != handler.thread_id:
                # TODO: we should allow multiple handlers at the same syscall (e.g., for different threads)
                handler.thread_id = thread_id
                liblog.warning(
                    f"Syscall {resolve_syscall_name(self.arch, original_syscall_number)} is already handled by another "
                    "thread. Overriding it.",
                )
            handler.on_enter_user = on_enter
            handler.on_exit_user = None
            handler.recursive = recursive
            handler.enabled = True
        else:
            handler = SyscallHandler(
                original_syscall_number,
                thread_id,
                on_enter,
                None,
                None,
                None,
                recursive,
            )

            link_to_internal_debugger(handler, self)

            self.__polling_thread_command_queue.put(
                (self.__threaded_handle_syscall, (handler,)),
            )

            self._join_and_check_status()

        return handler

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def gdb(
        self: InternalDebugger,
        migrate_breakpoints: bool = True,
        open_in_new_process: bool = True,
        blocking: bool = True,
    ) -> GdbResumeEvent:
        """Migrates the current debugging session to GDB."""
        # TODO: not needed?
        self.interrupt()

        self.__polling_thread_command_queue.put((self.__threaded_gdb, ()))

        self._join_and_check_status()

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

        resume_event = GdbResumeEvent(self, lambda_fun)

        self._is_migrated_to_gdb = True

        if blocking:
            resume_event.join()
            return None
        else:
            return resume_event

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
        gdb_command = f'/bin/gdb -q --pid {self.process_id} -ex "source {GDB_GOBACK_LOCATION} " -ex "ni" -ex "ni"'

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

                if self.internal_threads[0].instruction_pointer == bp.address and not bp.hardware:
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
            temp_file.write("#!/bin/bash\n")
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
        # Create the command to open the terminal and run the script
        command = [*libcontext.terminal, script_path]

        # Open GDB in a new terminal
        terminal_pid = Popen(command).pid

        # This is the command line that we are looking for
        cmdline_target = ["/bin/bash", script_path]

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
        gdb_pid = os.fork()

        if gdb_pid == 0:  # This is the child process.
            os.execv("/bin/bash", ["/bin/bash", script_path])
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
        self.__polling_thread_command_queue.put((self.__threaded_migrate_from_gdb, ()))

        self._join_and_check_status()

        self._is_migrated_to_gdb = False

    def _background_step(self: InternalDebugger, thread: InternalThreadContext) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (InternalThreadContext): The thread to step. Defaults to None.
        """
        self.__threaded_step(thread)
        self.__threaded_wait()

    @background_alias(_background_step)
    @change_state_function_process
    def step(self: InternalDebugger, thread: InternalThreadContext = None) -> None:
        """Executes a single instruction of the specified thread or all threads.

        If the thread is not specified, the command will be executed on all threads.

        Args:
            thread (InternalThreadContext, optional): The thread to step. Defaults to None, which means all threads.
        """
        # TODO: it should not be always a state_function_process, we should change the decorator
        self.__polling_thread_command_queue.put((self.__threaded_step, (thread,)))
        # TODO: this function should not be blocking
        self._join_and_check_status()

    def _background_step_until(
        self: InternalDebugger,
        thread: InternalThreadContext,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            thread (InternalThreadContext): The thread to step. Defaults to None.
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)

        self.__threaded_step_until(thread, address, max_steps)

    @background_alias(_background_step_until)
    @change_state_function_process
    def step_until(
        self: InternalDebugger,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
        thread: InternalThreadContext = None,
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        If the thread is not specified, the command will be executed on all threads.

        Args:
            thread (InternalThreadContext): The thread to step. Defaults to None, which means all threads.
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        # TODO: it should not be always a state_function_process, we should change the decorator
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)

        arguments = (
            thread,
            address,
            max_steps,
        )

        self.__polling_thread_command_queue.put((self.__threaded_step_until, arguments))

        # TODO: this function should not be blocking
        self._join_and_check_status()

    def _background_finish(
        self: InternalDebugger,
        thread: InternalThreadContext,
        heuristic: str = "backtrace",
    ) -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            thread (InternalThreadContext): The thread to finish.
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self.__threaded_finish(thread, heuristic)

    @background_alias(_background_finish)
    @change_state_function_process
    def finish(self: InternalDebugger, heuristic: str = "backtrace", thread: InternalThreadContext = None) -> None:
        """Continues execution until the current function returns or the process stops.

        If the thread is not specified, the command will be executed on all threads.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
            thread (InternalThreadContext, optional): The thread to finish. Defaults to None, which means all threads.
        """
        # TODO: it should not be always a state_function_process, we should change the decorator
        self.__polling_thread_command_queue.put(
            (self.__threaded_finish, (thread, heuristic)),
        )

        # TODO: this function should not be blocking
        self._join_and_check_status()

    def _background_next(
        self: InternalDebugger,
        thread: InternalThreadContext,
    ) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self.__threaded_next(thread)

    @background_alias(_background_next)
    @change_state_function_thread
    def next(self: InternalDebugger, thread: InternalThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        # TODO: it should not be always a state_function_process, we should change the decorator
        self.ensure_process_stopped()
        self.__polling_thread_command_queue.put((self.__threaded_next, (thread,)))
        # TODO: this function should not be blocking
        self._join_and_check_status()

    def enable_pretty_print(
        self: InternalDebugger,
    ) -> SyscallHandler:
        """Handles a syscall in the target process to pretty prints its arguments and return value."""
        self.ensure_process_stopped()

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
                    if handler.thread_id != -1:
                        handler.thread_id = -1
                        liblog.warning(
                            "A pretty printed syscall is already handled for a specific thread."
                            "The existing handler will become process-wide. This will be solved in future releases.",
                        )
                else:
                    # Remove the pretty print handler from previous pretty print calls
                    handler.on_enter_pprint = None
                    handler.on_exit_pprint = None

            elif syscall_number not in (self.syscalls_to_not_pprint or []) and syscall_number in (
                self.syscalls_to_pprint or syscall_numbers
            ):
                handler = SyscallHandler(
                    syscall_number,
                    -1,
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
        self.ensure_process_stopped()

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

    def insert_new_thread(self: InternalDebugger, thread: InternalThreadContext) -> None:
        """Insert a new thread in the context.

        Args:
            thread (InternalThreadContext): the thread to insert.
        """
        if thread in self.internal_threads:
            raise RuntimeError("Thread already registered.")

        self.internal_threads.append(thread)
        public_thread = ThreadContext(thread)
        self.public_threads.append(ThreadContext(thread))
        thread.public_thread_context = public_thread

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
        thread = self.get_thread_by_id(thread_id)
        thread.running = False
        thread.scheduled = False
        thread.dead = True
        thread.exit_code = exit_code
        thread.exit_signal = exit_signal

    def get_thread_by_id(self: InternalDebugger, thread_id: int) -> InternalThreadContext:
        """Get a thread by its ID.

        Args:
            thread_id (int): the ID of the thread to get.

        Returns:
            InternalThreadContext: the thread with the specified ID.
        """
        for thread in self.internal_threads:
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
                    f"No backing file specified and no corresponding absolute address found for {hex(address)}. Assuming {backing_file}.",
                )

        filtered_maps = maps.filter(backing_file)

        return normalize_and_validate_address(address, filtered_maps)

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
            # If no explicit backing file is specified, we have to assume it is in the main map
            backing_file = self._process_full_path
            liblog.debugger(f"No backing file specified for the symbol {symbol}. Assuming {backing_file}.")
        elif backing_file in ["binary", self._process_name]:
            backing_file = self._process_full_path

        filtered_maps = self.maps.filter(backing_file)

        return resolve_symbol_in_maps(symbol, filtered_maps)

    @property
    def symbols(self: InternalDebugger) -> SymbolList[Symbol]:
        """Get the symbols of the process."""
        self.ensure_process_stopped()
        backing_files = {vmap.backing_file for vmap in self.maps}
        with extend_internal_debugger(self):
            return get_all_symbols(backing_files)

    def _background_ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        # There is no case where this should ever happen, but...
        if self._is_migrated_to_gdb:
            raise RuntimeError("Cannot execute this command after migrating to GDB.")

    @background_alias(_background_ensure_process_stopped)
    def ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        # TODO: for thread-safe resources we should use a lock that is thread-based, not process-based
        if self._is_migrated_to_gdb:
            raise RuntimeError("Cannot execute this command after migrating to GDB.")

        if not self.any_thread_running:
            return

        if self.auto_interrupt_on_command:
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
            except BaseException as e:
                return_value = e

            if return_value is not None:
                self.__polling_thread_response_queue.put(return_value)

            # Signal that the command has been executed
            self.__polling_thread_command_queue.task_done()

            if return_value is not None:
                self.__polling_thread_response_queue.join()

    def _join_and_check_status(self: InternalDebugger) -> None:
        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self.__polling_thread_command_queue.join()

        # Check for any exceptions raised by the background thread
        if not self.__polling_thread_response_queue.empty():
            response = self.__polling_thread_response_queue.get()
            self.__polling_thread_response_queue.task_done()
            if response is not None:
                raise response

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
        liblog.debugger("Starting process %s.", self.argv[0])
        self.debugging_interface.run(redirect_pipes)

    def __threaded_attach(self: InternalDebugger, pid: int) -> None:
        liblog.debugger("Attaching to process %d.", pid)
        self.debugging_interface.attach(pid)

    def __threaded_detach(self: InternalDebugger) -> None:
        liblog.debugger("Detaching from process %d.", self.process_id)
        self.debugging_interface.detach()

    def __threaded_kill(self: InternalDebugger) -> None:
        if self.argv:
            liblog.debugger(
                "Killing process %s (%d).",
                self.argv[0],
                self.process_id,
            )
        else:
            liblog.debugger("Killing process %d.", self.process_id)
        self.debugging_interface.kill()

    def __threaded_cont(self: InternalDebugger, thread: InternalThreadContext) -> None:
        # TODO: what if I need to continue N threads with N != len(internal_threads)?
        if self.argv:
            liblog.debugger(
                "Continuing %s (%s: %d).",
                self.argv[0],
                "pid" if thread is None else "tid",
                self.process_id if thread is None else thread.thread_id,
            )
        else:
            liblog.debugger("Continuing %d.", self.process_id if thread is None else thread.thread_id)

        if thread is None:
            self.set_all_threads_running()
            self.set_all_threads_scheduled()
        else:
            thread.running = True
            thread.scheduled = True
        self.debugging_interface.cont(thread)

    def __threaded_wait(self: InternalDebugger, thread: InternalThreadContext = None) -> None:
        # TODO: what if I need to wait N threads with N != len(internal_threads)?
        if self.argv:
            liblog.debugger(
                "Waiting for %s (%s: %d) to stop.",
                self.argv[0],
                "pid" if thread is None else "tid",
                self.process_id if thread is None else thread.thread_id,
            )
        else:
            liblog.debugger("Waiting for %d to stop.", self.process_id if thread is None else thread.thread_id)

        while True:
            self.resume_context.resume = True
            self.debugging_interface.wait(thread)
            if self.internal_threads[0].dead:
                # All threads are dead
                liblog.debugger("All threads dead")
                break
            if thread is not None and thread.dead:
                # The thread is dead
                liblog.debugger("Thread %d dead", thread.thread_id)
                break
            if self.resume_context.resume:
                if thread is not None:
                    # We need to continue only the specified thread
                    self.debugging_interface.cont(thread)
                elif self.all_threads_scheduled:
                    # We need to continue all threads, we can just call cont process-wide
                    self.debugging_interface.cont()
                else:
                    # We need to continue only the scheduled threads, we need to call cont for each thread
                    for t in self.internal_threads:
                        if t.scheduled:
                            self.debugging_interface.cont(t)
            else:
                break
        if thread is None:
            self.set_all_threads_stopped()
        else:
            thread.running = False

    def __threaded_breakpoint(self: InternalDebugger, bp: Breakpoint, thread_id: int) -> None:
        liblog.debugger(
            f"Setting breakpoint at {bp.address:x}" + (f" for thread {thread_id}" if thread_id != -1 else "."),
        )
        self.debugging_interface.set_breakpoint(bp, thread_id)

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

    def __threaded_step(self: InternalDebugger, thread: InternalThreadContext) -> None:
        # TODO: what if I need to step N threads with N != len(internal_threads)?
        # TODO: better manage the running flag while stepping
        liblog.debugger("Stepping thread " + (f"{thread.thread_id}." if thread is not None else "all threads."))
        self.debugging_interface.step(thread)
        self.set_all_threads_stopped()

    def __threaded_step_until(
        self: InternalDebugger,
        thread: InternalThreadContext,
        address: int,
        max_steps: int,
    ) -> None:
        # TODO: better manage the running flag while stepping
        # TODO: what if I need to continue N threads with N != len(internal_threads)?
        liblog.debugger("Stepping " + (f"thread {thread.thread_id}." if thread is not None else "all threads."))
        self.debugging_interface.step_until(thread, address, max_steps)
        self.set_all_threads_stopped()

    def __threaded_finish(self: InternalDebugger, thread: InternalThreadContext, heuristic: str) -> None:
        # TODO: better manage the running flag while finishing
        # TODO: what if I need to call finish on N threads with N != len(internal_threads)?
        prefix = heuristic.capitalize()

        liblog.debugger(
            f"{prefix} finish on" + (f" thread {thread.thread_id}." if thread is not None else " all threads."),
        )
        self.debugging_interface.finish(thread, heuristic=heuristic)

        self.set_all_threads_stopped()

    def __threaded_next(self: InternalDebugger, thread: InternalThreadContext) -> None:
        # TODO: better manage the running flag while executing next
        # TODO: what if I need to call next on N threads with N != len(internal_threads)?
        liblog.debugger("Next on thread %s.", thread.thread_id)
        self.debugging_interface.next(thread)
        self.set_all_threads_stopped()

    def __threaded_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_to_gdb()

    def __threaded_migrate_from_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_from_gdb()

    def __threaded_peek_memory(self: InternalDebugger, address: int) -> bytes | BaseException:
        value = self.debugging_interface.peek_memory(address)
        return value.to_bytes(get_platform_register_size(libcontext.platform), sys.byteorder)

    def __threaded_poke_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        int_data = int.from_bytes(data, sys.byteorder)
        self.debugging_interface.poke_memory(address, int_data)

    def __threaded_fetch_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        self.debugging_interface.fetch_fp_registers(registers)

    def __threaded_flush_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        self.debugging_interface.flush_fp_registers(registers)

    @background_alias(__threaded_peek_memory)
    def _peek_memory(self: InternalDebugger, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.any_thread_running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before reading memory.",
            )

        self.ensure_process_stopped()

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

        if self.any_thread_running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before reading memory.",
            )

        self.ensure_process_stopped()

        return self._process_memory_manager.read(address, size)

    @background_alias(__threaded_poke_memory)
    def _poke_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.any_thread_running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before writing to memory.",
            )

        self.ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_poke_memory, (address, data)),
        )

        self._join_and_check_status()

    def _fast_write_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot access memory.")

        if self.any_thread_running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before writing to memory.",
            )

        self.ensure_process_stopped()

        self._process_memory_manager.write(address, data)

    @background_alias(__threaded_fetch_fp_registers)
    def _fetch_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        """Fetches the floating point registers of a thread."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot read floating-point registers.")

        self.ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_fetch_fp_registers, (registers,)),
        )

        self._join_and_check_status()

    @background_alias(__threaded_flush_fp_registers)
    def _flush_fp_registers(self: InternalDebugger, registers: Registers) -> None:
        """Flushes the floating point registers of a thread."""
        if not self.is_debugging:
            raise RuntimeError("Process not running, cannot write floating-point registers.")

        self.ensure_process_stopped()

        self.__polling_thread_command_queue.put(
            (self.__threaded_flush_fp_registers, (registers,)),
        )

        self._join_and_check_status()

    def _enable_antidebug_escaping(self: InternalDebugger) -> None:
        """Enables the anti-debugging escape mechanism."""
        handler = SyscallHandler(
            resolve_syscall_number(self.arch, "ptrace"),
            -1,
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
    def any_thread_running(self: InternalDebugger) -> bool:
        """Check if any thread is running.

        Returns:
            bool: True if any thread is running, False otherwise.
        """
        return any(thread.running for thread in self.internal_threads)

    @property
    def all_threads_running(self: InternalDebugger) -> bool:
        """Check if all threads are running.

        Returns:
            bool: True if all threads are running, False otherwise.
        """
        return all(thread.running for thread in self.internal_threads)

    @property
    def any_thread_scheduled(self: InternalDebugger) -> bool:
        """Check if any thread is scheduled.

        Returns:
            bool: True if any thread is scheduled, False otherwise.
        """
        return any(thread.scheduled for thread in self.internal_threads)

    @property
    def all_threads_scheduled(self: InternalDebugger) -> bool:
        """Check if all threads are scheduled.

        Returns:
            bool: True if all threads are scheduled, False otherwise.
        """
        return all(thread.scheduled for thread in self.internal_threads)

    def set_all_threads_running(self: InternalDebugger) -> None:
        """Set the state of all threads to running."""
        for thread in self.internal_threads:
            thread.running = True

    def set_all_threads_scheduled(self: InternalDebugger) -> None:
        """Set the state of all threads to scheduled."""
        for thread in self.internal_threads:
            thread.scheduled = True

    def set_all_threads_stopped(self: InternalDebugger) -> None:
        """Set the state of all threads to stopped."""
        for thread in self.internal_threads:
            thread.running = False
