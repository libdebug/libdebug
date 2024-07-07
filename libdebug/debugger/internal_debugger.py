#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


from __future__ import annotations

import functools
import os
import signal
from pathlib import Path
from queue import Queue
from signal import SIGKILL, SIGSTOP, SIGTRAP
from subprocess import Popen
from threading import Thread, current_thread
from typing import TYPE_CHECKING

import psutil

from libdebug.architectures.syscall_hijacking_provider import syscall_hijacking_provider
from libdebug.builtin.antidebug_syscall_handler import on_enter_ptrace, on_exit_ptrace
from libdebug.builtin.pretty_print_syscall_handler import pprint_on_enter, pprint_on_exit
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.data.signal_catcher import SignalCatcher
from libdebug.data.syscall_handler import SyscallHandler
from libdebug.debugger.internal_debugger_instance_manager import (
    extend_internal_debugger,
    link_to_internal_debugger,
)
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.state.resume_context import ResumeContext
from libdebug.utils.debugger_wrappers import (
    background_alias,
    change_state_function_process,
    change_state_function_thread,
)
from libdebug.utils.debugging_utils import (
    check_absolute_address,
    normalize_and_validate_address,
    resolve_symbol_in_maps,
)
from libdebug.utils.libcontext import libcontext
from libdebug.utils.print_style import PrintStyle
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

    from libdebug.data.memory_map import MemoryMap
    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.state.thread_context import ThreadContext
    from libdebug.utils.pipe_manager import PipeManager

THREAD_TERMINATE = -1
GDB_GOBACK_LOCATION = str((Path(__file__).parent / "utils" / "gdb.py").resolve())


class InternalDebugger:
    """A class that holds the global debugging state."""

    aslr_enabled: bool
    """A flag that indicates if ASLR is enabled or not."""

    argv: list[str]
    """The command line arguments of the debugged process."""

    env: dict[str, str] | None
    """The environment variables of the debugged process."""

    escape_antidebug: bool
    """A flag that indicates if the debugger should escape anti-debugging techniques."""

    autoreach_entrypoint: bool
    """A flag that indicates if the debugger should automatically reach the entry point of the debugged process."""

    auto_interrupt_on_command: bool
    """A flag that indicates if the debugger should automatically interrupt the debugged process when a command is issued."""

    breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process.
    Key: the address of the breakpoint."""

    handled_syscalls: dict[int, SyscallHandler]
    """A dictionary of all the syscall handled in the process.
    Key: the syscall number."""

    caught_signals: dict[int, SignalCatcher]
    """A dictionary of all the signals caught in the process.
    Key: the signal number."""

    signals_to_block: list[int]
    """The signals to not forward to the process."""

    syscalls_to_pprint: list[int] | None
    """The syscalls to pretty print."""

    syscalls_to_not_pprint: list[int] | None
    """The syscalls to not pretty print."""

    threads: list[ThreadContext]
    """A list of all the threads of the debugged process."""

    process_id: int
    """The PID of the debugged process."""

    pipe_manager: PipeManager
    """The pipe manager used to communicate with the debugged process."""

    memory: MemoryView
    """The memory view of the debugged process."""

    debugging_interface: DebuggingInterface
    """The debugging interface used to communicate with the debugged process."""

    instanced: bool = False
    """Whether the process was started and has not been killed yet."""

    pprint_syscalls: bool
    """A flag that indicates if the debugger should pretty print syscalls."""

    resume_context: ResumeContext
    """Context that indicates if the debugger should resume the debugged process."""

    _polling_thread: Thread | None
    """The background thread used to poll the process for state change."""

    _polling_thread_command_queue: Queue | None
    """The queue used to send commands to the background thread."""

    _polling_thread_response_queue: Queue | None
    """The queue used to receive responses from the background thread."""

    _is_running: bool
    """The overall state of the debugged process. True if the process is running, False otherwise."""

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
        self.threads = list()
        self.instanced = False
        self._is_running = False
        self.resume_context = ResumeContext()
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
        self.threads.clear()
        self.instanced = False
        self._is_running = False
        self.resume_context.clear()

    def start_up(self: InternalDebugger) -> None:
        """Starts up the context."""

        # The context is linked to itself
        link_to_internal_debugger(self, self)

        self.start_processing_thread()
        with extend_internal_debugger(self):
            self.debugging_interface = provide_debugging_interface()
            self.memory = MemoryView(self._peek_memory, self._poke_memory)

    def start_processing_thread(self: InternalDebugger) -> None:
        """Starts the thread that will poll the traced process for state change."""
        # Set as daemon so that the Python interpreter can exit even if the thread is still running
        self.__polling_thread = Thread(
            target=self.__polling_thread_function,
            name="libdebug__polling_thread",
            daemon=True,
        )
        self.__polling_thread.start()

    def _background_invalid_call(self: InternalDebugger) -> None:
        """Raises an error when an invalid call is made in background mode."""
        raise RuntimeError("This method is not available in a callback.")

    def run(self: InternalDebugger) -> None:
        """Starts the process and waits for it to stop."""
        if not self.argv:
            raise RuntimeError("No binary file specified.")

        if not Path(self.argv[0]).is_file():
            raise RuntimeError(f"File {self.argv[0]} does not exist.")

        if not os.access(self.argv[0], os.X_OK):
            raise RuntimeError(
                f"File {self.argv[0]} is not executable.",
            )

        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.threads:
            self.clear()
            self.debugging_interface.reset()

        self.instanced = True

        if not self.__polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self.__polling_thread_command_queue.put((self.__threaded_run, ()))

        if self.escape_antidebug:
            liblog.debugger("Enabling anti-debugging escape mechanism.")
            self._enable_antidebug_escaping()

        self._join_and_check_status()

        if not self.pipe_manager:
            raise RuntimeError("Something went wrong during pipe initialization.")

        return self.pipe_manager

    def attach(self: InternalDebugger, pid: int) -> None:
        """Attaches to an existing process."""
        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()
        if self.threads:
            self.clear()
            self.debugging_interface.reset()

        self.instanced = True

        if not self.__polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self.__polling_thread_command_queue.put((self.__threaded_attach, (pid,)))

        self._join_and_check_status()

    def detach(self: InternalDebugger) -> None:
        """Detaches from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot detach.")

        self._ensure_process_stopped()

        self.__polling_thread_command_queue.put((self.__threaded_detach, ()))

        self._join_and_check_status()

    @background_alias(_background_invalid_call)
    def kill(self: InternalDebugger) -> None:
        """Kills the process."""
        try:
            self._ensure_process_stopped()
        except (OSError, RuntimeError):
            # This exception might occur if the process has already died
            liblog.debugger("OSError raised during kill")

        self.__polling_thread_command_queue.put((self.__threaded_kill, ()))

        self.instanced = False

        if self.pipe_manager:
            self.pipe_manager.close()

        self._join_and_check_status()

    def terminate(self: InternalDebugger) -> None:
        """Terminates the background thread.

        The debugger object cannot be used after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        if self.__polling_thread is not None:
            self.__polling_thread_command_queue.put((THREAD_TERMINATE, ()))
            self.__polling_thread.join()
            del self.__polling_thread
            self.__polling_thread = None

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def cont(self: InternalDebugger) -> None:
        """Continues the process.

        Args:
            auto_wait (bool, optional): Whether to automatically wait for the process to stop after continuing. Defaults to True.
        """
        self.__polling_thread_command_queue.put((self.__threaded_cont, ()))

        self._join_and_check_status()

        self.__polling_thread_command_queue.put((self.__threaded_wait, ()))

    @background_alias(_background_invalid_call)
    def interrupt(self: InternalDebugger) -> None:
        """Interrupts the process."""
        if not self.instanced:
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
        if not self.instanced:
            raise RuntimeError("Process not running, cannot wait.")

        self._join_and_check_status()

        if self.threads[0].dead or not self.running:
            # Most of the time the function returns here, as there was a wait already
            # queued by the previous command
            return

        self.__polling_thread_command_queue.put((self.__threaded_wait, ()))

        self._join_and_check_status()

    def maps(self: InternalDebugger) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        self._ensure_process_stopped()
        return self.debugging_interface.maps()

    def print_maps(self: InternalDebugger) -> None:
        """Prints the memory maps of the process."""
        self._ensure_process_stopped()
        maps = self.maps()
        for memory_map in maps:
            if "x" in memory_map.permissions:
                print(f"{PrintStyle.RED}{memory_map}{PrintStyle.RESET}")
            elif "w" in memory_map.permissions:
                print(f"{PrintStyle.YELLOW}{memory_map}{PrintStyle.RESET}")
            elif "r" in memory_map.permissions:
                print(f"{PrintStyle.GREEN}{memory_map}{PrintStyle.RESET}")
            else:
                print(memory_map)

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def breakpoint(
        self: InternalDebugger,
        position: int | str,
        hardware: bool = False,
        condition: str | None = None,
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software.
            Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the
            breakpoint is hit. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid"
            (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t.
            the "binary" map file).
        """
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)
            position = hex(address)

        if condition:
            if not hardware:
                raise ValueError(
                    "Breakpoint condition is supported only for hardware watchpoints.",
                )

            if condition.lower() not in ["w", "rw", "x"]:
                raise ValueError(
                    "Invalid condition for watchpoints. Supported conditions are 'w', 'rw', 'x'.",
                )

            if length not in [1, 2, 4, 8]:
                raise ValueError(
                    "Invalid length for watchpoints. Supported lengths are 1, 2, 4, 8.",
                )

        if hardware and not condition:
            condition = "x"

        bp = Breakpoint(address, position, 0, hardware, callback, condition, length)

        link_to_internal_debugger(bp, self)

        self.__polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))

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
        callback: None | Callable[[ThreadContext, SignalCatcher], None] = None,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Catch a signal in the target process.

        Args:
            signal (int | str): The signal to catch.
            callback (Callable[[ThreadContext, CaughtSignal], None], optional): A callback to be called when the signal is
            caught. Defaults to None.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher
            associated with the new signal should be considered as well. Defaults to False.

        Returns:
            CaughtSignal: The CaughtSignal object.
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
                    f"Cannot catch SIGKILL ({signal_number}) as it cannot be caught or ignored. This is a kernel restriction."
                )
            case SIGSTOP.value:
                raise ValueError(
                    f"Cannot catch SIGSTOP ({signal_number}) as it is used by the debugger or ptrace for their internal operations."
                )
            case SIGTRAP.value:
                raise ValueError(
                    f"Cannot catch SIGTRAP ({signal_number}) as it is used by the debugger or ptrace for their internal operations."
                )

        if signal_number in self.caught_signals:
            liblog.warning(
                f"Signal {resolve_signal_name(signal_number)} ({signal_number}) has already been caught. Overriding it.",
            )

        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")

        catcher = SignalCatcher(signal_number, callback, recursive)

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
    ) -> SignalCatcher:
        """Hijack a signal in the target process.

        Args:
            original_signal (int | str): The signal to hijack.
            new_signal (int | str): The signal to hijack the original signal with.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher
            associated with the new signal should be considered as well. Defaults to False.

        Returns:
            CaughtSignal: The CaughtSignal object.
        """
        if isinstance(original_signal, str):
            original_signal_number = resolve_signal_number(original_signal)
        else:
            original_signal_number = original_signal

        new_signal_number = resolve_signal_number(new_signal) if isinstance(new_signal, str) else new_signal

        if original_signal_number == new_signal_number:
            raise ValueError(
                "The original signal and the new signal must be different during hijacking.",
            )

        def callback(thread: ThreadContext, _: SignalCatcher) -> None:
            """The callback to execute when the signal is received."""
            thread.signal = new_signal_number

        return self.catch_signal(original_signal_number, callback, recursive)

    @background_alias(_background_invalid_call)
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
            syscall (int | str): The syscall name or number to handle.
            on_enter (Callable[[ThreadContext, HandledSyscall], None], optional): The callback to execute when the
            syscall is entered. Defaults to None.
            on_exit (Callable[[ThreadContext, HandledSyscall], None], optional): The callback to execute when the
            syscall is exited. Defaults to None.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler
            associated with the new syscall should be considered as well. Defaults to False.

        Returns:
            HandledSyscall: The HandledSyscall object.
        """
        syscall_number = resolve_syscall_number(syscall) if isinstance(syscall, str) else syscall

        if not isinstance(recursive, bool):
            raise TypeError("recursive must be a boolean")

        # Check if the syscall is already handled (by the user or by the pretty print handler)
        if syscall_number in self.handled_syscalls:
            handler = self.handled_syscalls[syscall_number]
            if handler.on_enter_user or handler.on_exit_user:
                liblog.warning(
                    f"Syscall {resolve_syscall_name(syscall_number)} is already handled by a user-defined handler. Overriding it.",
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
        **kwargs: int,
    ) -> SyscallHandler:
        """Hijacks a syscall in the target process.

        Args:
            original_syscall (int | str): The syscall name or number to hijack.
            new_syscall (int | str): The syscall name or number to hijack the original syscall with.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler
            associated with the new syscall should be considered as well. Defaults to False.
            **kwargs: (int, optional): The arguments to pass to the new syscall.

        Returns:
            HandledSyscall: The HandledSyscall object.
        """
        if set(kwargs) - syscall_hijacking_provider().allowed_args:
            raise ValueError("Invalid keyword arguments in syscall hijack")

        if isinstance(original_syscall, str):
            original_syscall_number = resolve_syscall_number(original_syscall)
        else:
            original_syscall_number = original_syscall

        new_syscall_number = resolve_syscall_number(new_syscall) if isinstance(new_syscall, str) else new_syscall

        if original_syscall_number == new_syscall_number:
            raise ValueError(
                "The original syscall and the new syscall must be different during hijacking.",
            )

        on_enter = syscall_hijacking_provider().create_hijacker(
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

            self.__polling_thread_command_queue.put(
                (self.__threaded_handle_syscall, (handler,)),
            )

            self._join_and_check_status()

        return handler

    @background_alias(_background_invalid_call)
    @change_state_function_process
    def gdb(self: InternalDebugger, open_in_new_process: bool = True) -> None:
        """Migrates the current debugging session to GDB."""

        # TODO: not needed?
        self.interrupt()

        self.__polling_thread_command_queue.put((self.__threaded_gdb, ()))

        self._join_and_check_status()

        if open_in_new_process and libcontext.terminal:
            self._open_gdb_in_new_process()
        else:
            if open_in_new_process:
                liblog.warning(
                    "Cannot open in a new process. Please configure the terminal in libcontext.terminal.",
                )
            self._open_gdb_in_shell()

        self.__polling_thread_command_queue.put((self.__threaded_migrate_from_gdb, ()))

        self._join_and_check_status()

    def _craft_gdb_migration_command(self: InternalDebugger) -> list[str]:
        """Crafts the command to migrate to GDB."""
        gdb_command = [
            "/bin/gdb",
            "-q",
            "--pid",
            str(self.process_id),
            "-ex",
            "source " + GDB_GOBACK_LOCATION,
            "-ex",
            "ni",
            "-ex",
            "ni",
        ]

        bp_args = []
        for bp in self.breakpoints.values():
            if bp.enabled:
                bp_args.append("-ex")

                if bp.hardware and bp.condition == "rw":
                    bp_args.append(f"awatch *(int{bp.length * 8}_t *) {bp.address:0x}")
                elif bp.hardware and bp.condition == "w":
                    bp_args.append(f"watch *(int{bp.length * 8}_t *) {bp.address:0x}")
                elif bp.hardware:
                    bp_args.append("hb *" + hex(bp.address))
                else:
                    bp_args.append("b *" + hex(bp.address))

                if self.threads[0].instruction_pointer == bp.address and not bp.hardware:
                    # We have to enqueue an additional continue
                    bp_args.append("-ex")
                    bp_args.append("ni")

        return gdb_command + bp_args

    def _open_gdb_in_new_process(self: InternalDebugger) -> None:
        """Opens GDB in a new process following the configuration in libcontext.terminal."""
        args = self._craft_gdb_migration_command()

        initial_pid = Popen(libcontext.terminal + args).pid

        os.waitpid(initial_pid, 0)

        liblog.debugger("Waiting for GDB process to terminate...")

        for proc in psutil.process_iter():
            try:
                cmdline = proc.cmdline()
            except psutil.ZombieProcess:
                # This is a zombie process, which psutil tracks but we cannot interact with
                continue

            if args == cmdline:
                gdb_process = proc
                break
        else:
            raise RuntimeError("GDB process not found.")

        while gdb_process.is_running() and gdb_process.status() != psutil.STATUS_ZOMBIE:
            # As the GDB process is in a different group, we do not have the authority to wait on it
            # So we must keep polling it until it is no longer running
            pass

    def _open_gdb_in_shell(self: InternalDebugger) -> None:
        """Open GDB in the current shell."""
        gdb_pid = os.fork()
        if gdb_pid == 0:  # This is the child process.
            args = self._craft_gdb_migration_command()
            os.execv("/bin/gdb", args)
        else:  # This is the parent process.
            # Parent ignores SIGINT, so only GDB (child) receives it
            signal.signal(signal.SIGINT, signal.SIG_IGN)

            # Wait for the child process to finish
            os.waitpid(gdb_pid, 0)

            # Reset the SIGINT behavior to default handling after child exits
            signal.signal(signal.SIGINT, signal.SIG_DFL)

    def _background_step(self: InternalDebugger, thread: ThreadContext) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext): The thread to step. Defaults to None.
        """
        self.__threaded_step(thread)
        self.__threaded_wait()

    @background_alias(_background_step)
    @change_state_function_thread
    def step(self: InternalDebugger, thread: ThreadContext) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext): The thread to step. Defaults to None.
        """
        self._ensure_process_stopped()
        self.__polling_thread_command_queue.put((self.__threaded_step, (thread,)))
        self.__polling_thread_command_queue.put((self.__threaded_wait, ()))
        self._join_and_check_status()

    def _background_step_until(
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
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid"
            (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t.
            the "binary" map file).
        """
        if isinstance(position, str):
            address = self.resolve_symbol(position, file)
        else:
            address = self.resolve_address(position, file)

        self.__threaded_step_until(thread, address, max_steps)

    @background_alias(_background_step_until)
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
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid"
            (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t.
            the "binary" map file).
        """
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

        self._join_and_check_status()

    def _background_finish(
        self: InternalDebugger,
        thread: ThreadContext,
        heuristic: str = "backtrace",
    ) -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            thread (ThreadContext): The thread to finish.
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self.__threaded_finish(thread, heuristic)

    @background_alias(_background_finish)
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
        self.__polling_thread_command_queue.put(
            (self.__threaded_finish, (thread, heuristic)),
        )

        self._join_and_check_status()

    def enable_pretty_print(
        self: InternalDebugger,
    ) -> SyscallHandler:
        """Handles a syscall in the target process to pretty prints its arguments and return value."""
        self._ensure_process_stopped()

        syscall_numbers = get_all_syscall_numbers()

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

    def resolve_address(self: InternalDebugger, address: int, backing_file: str) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.
            backing_file (str): The backing file to resolve the address in.

        Returns:
            int: The normalized and validated address.

        Raises:
            ValueError: If the substring `backing_file` is present in multiple backing files.
        """
        maps = self.debugging_interface.maps()

        if backing_file in ["hybrid", "absolute"]:
            if check_absolute_address(address, maps):
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
                backing_file = self._get_process_full_path()
                liblog.warning(
                    f"No backing file specified and no corresponding absolute address found for {hex(address)}. Assuming {backing_file}.",
                )
        elif (
            backing_file == (full_backing_path := self._get_process_full_path())
            or backing_file == "binary"
            or backing_file == self._get_process_name()
        ):
            backing_file = full_backing_path

        filtered_maps = []
        unique_files = set()

        for vmap in maps:
            if backing_file in vmap.backing_file:
                filtered_maps.append(vmap)
                unique_files.add(vmap.backing_file)

        if len(unique_files) > 1:
            raise ValueError(
                f"The substring {backing_file} is present in multiple, different backing files. The address resolution cannot be accurate. The matching backing files are: {', '.join(unique_files)}.",
            )

        if not filtered_maps:
            raise ValueError(
                f"The specified string {backing_file} does not correspond to any backing file. The available backing files are: {', '.join(set(vmap.backing_file for vmap in maps))}."
            )
        return normalize_and_validate_address(address, filtered_maps)

    def resolve_symbol(self: InternalDebugger, symbol: str, backing_file: str) -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.
            backing_file (str): The backing file to resolve the symbol in.

        Returns:
            int: The address of the symbol.
        """
        maps = self.debugging_interface.maps()

        if backing_file == "absolute":
            raise ValueError("Cannot use `absolute` backing file with symbols.")

        if backing_file == "hybrid":
            # If no explicit backing file is specified, we have to assume it is in the main map
            backing_file = self._get_process_full_path()
            liblog.debugger(f"No backing file specified for the symbol {symbol}. Assuming {backing_file}.")
        elif (
            backing_file == (full_backing_path := self._get_process_full_path())
            or backing_file == "binary"
            or backing_file == self._get_process_name()
        ):
            backing_file = full_backing_path

        filtered_maps = []
        unique_files = set()

        for vmap in maps:
            if backing_file in vmap.backing_file:
                filtered_maps.append(vmap)
                unique_files.add(vmap.backing_file)

        if len(unique_files) > 1:
            raise ValueError(
                f"The substring {backing_file} is present in multiple, different backing files. The address resolution cannot be accurate. The matching backing files are: {', '.join(unique_files)}.",
            )

        if not filtered_maps:
            raise ValueError(
                f"The specified string {backing_file} does not correspond to any backing file. The available backing files are: {', '.join(set(vmap.backing_file for vmap in maps))}."
            )

        return resolve_symbol_in_maps(symbol, filtered_maps)

    def _background_ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        # In background mode, there shouldn't be anything to do here

    @background_alias(_background_ensure_process_stopped)
    def _ensure_process_stopped(self: InternalDebugger) -> None:
        """Validates the state of the process."""
        if not self.running:
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

    @functools.cache
    def _get_process_full_path(self: InternalDebugger) -> str:
        """Get the full path of the process.

        Returns:
            str: the full path of the process.
        """
        return str(Path(f"/proc/{self.process_id}/exe").readlink())

    @functools.cache
    def _get_process_name(self: InternalDebugger) -> str:
        """Get the name of the process.

        Returns:
            str: the name of the process.
        """
        with Path(f"/proc/{self.process_id}/comm").open() as f:
            return f.read().strip()

    def __threaded_run(self: InternalDebugger) -> None:
        liblog.debugger("Starting process %s.", self.argv[0])
        self.debugging_interface.run()

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
                self.argv[0],
                self.process_id,
            )
        else:
            liblog.debugger("Killing process %d.", self.process_id)
        self.debugging_interface.kill()

    def __threaded_cont(self: InternalDebugger) -> None:
        if self.argv:
            liblog.debugger(
                "Continuing process %s (%d).",
                self.argv[0],
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
                self.argv[0],
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
        self.set_running()

    def __threaded_step_until(
        self: InternalDebugger,
        thread: ThreadContext,
        address: int,
        max_steps: int,
    ) -> None:
        liblog.debugger("Stepping thread %s until 0x%x.", thread.thread_id, address)
        self.debugging_interface.step_until(thread, address, max_steps)
        self.set_stopped()

    def __threaded_finish(self: InternalDebugger, thread: ThreadContext, heuristic: str) -> None:
        prefix = heuristic.capitalize()

        liblog.debugger(f"{prefix} finish on thread %s", thread.thread_id)
        self.debugging_interface.finish(thread, heuristic=heuristic)

        self.set_stopped()

    def __threaded_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_to_gdb()

    def __threaded_migrate_from_gdb(self: InternalDebugger) -> None:
        self.debugging_interface.migrate_from_gdb()

    def __threaded_peek_memory(self: InternalDebugger, address: int) -> bytes | BaseException:
        try:
            value = self.debugging_interface.peek_memory(address)
            # TODO: this is only for amd64
            return value.to_bytes(8, "little")
        except BaseException as e:
            return e

    def __threaded_poke_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        int_data = int.from_bytes(data, "little")
        self.debugging_interface.poke_memory(address, int_data)

    @background_alias(__threaded_peek_memory)
    def _peek_memory(self: InternalDebugger, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

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

    @background_alias(__threaded_poke_memory)
    def _poke_memory(self: InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

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

    def _enable_antidebug_escaping(self: InternalDebugger) -> None:
        """Enables the anti-debugging escape mechanism."""
        handler = SyscallHandler(
            resolve_syscall_number("ptrace"),
            on_enter_ptrace,
            on_exit_ptrace,
            None,
            None,
        )

        link_to_internal_debugger(handler, self)

        self.__polling_thread_command_queue.put((self.__threaded_handle_syscall, (handler,)))

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
