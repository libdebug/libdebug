#
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import signal
from contextlib import contextmanager
from pathlib import Path
from queue import Queue
from subprocess import Popen
from threading import Thread, current_thread
from typing import TYPE_CHECKING

import psutil

from libdebug.architectures.syscall_hijacking_provider import syscall_hijacking_provider
from libdebug.builtin.antidebug_syscall_hook import on_enter_ptrace, on_exit_ptrace
from libdebug.builtin.pretty_print_syscall_hook import pprint_on_enter, pprint_on_exit
from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.data.signal_hook import SignalHook
from libdebug.data.syscall_hook import SyscallHook
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.liblog import liblog
from libdebug.state.debugging_context import (
    DebuggingContext,
    context_extend_from,
    create_context,
    link_context,
    provide_context,
)
from libdebug.state.resume_context import ResumeStatus
from libdebug.utils.debugger_wrappers import background_alias, control_flow_function
from libdebug.utils.libcontext import libcontext
from libdebug.utils.signal_utils import (
    get_all_signal_numbers,
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

    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.state.thread_context import ThreadContext


THREAD_TERMINATE = -1
GDB_GOBACK_LOCATION = str((Path(__file__).parent / "utils" / "gdb.py").resolve())


class _InternalDebugger:
    """The _InternalDebugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    memory: MemoryView | None = None
    """The memory view of the process."""

    breakpoints: dict[int, Breakpoint] = None
    """A dictionary of all the breakpoints set on the process. The keys are the absolute addresses of the breakpoints."""

    context: DebuggingContext | None = None
    """The debugging context of the process."""

    instanced: bool = False
    """Whether the process was started and has not been killed yet."""

    interface: DebuggingInterface | None = None
    """The debugging interface used to interact with the process."""

    threads: list[ThreadContext] = None
    """A dictionary of all the threads in the process. The keys are the thread IDs."""

    _polling_thread: Thread | None = None
    """The background thread used to poll the process for state change."""

    _polling_thread_command_queue: Queue | None = None
    """The queue used to send commands to the background thread."""

    _polling_thread_response_queue: Queue | None = None
    """The queue used to receive responses from the background thread."""

    def __init__(self: _InternalDebugger) -> None:
        pass

    def _post_init_(self: _InternalDebugger) -> None:
        """Do not use this constructor directly. Use the `debugger` function instead."""
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

    def terminate(self: _InternalDebugger) -> None:
        """Terminates the background thread.

        The debugger object cannot be used after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        if self._polling_thread is not None:
            self._polling_thread_command_queue.put((THREAD_TERMINATE, ()))
            self._polling_thread.join()
            del self._polling_thread
            self._polling_thread = None

    def run(self: _InternalDebugger) -> None:
        """Starts the process and waits for it to stop."""
        if not self.context.argv:
            raise RuntimeError("No binary file specified.")

        if not Path(provide_context(self).argv[0]).is_file():
            raise RuntimeError(f"File {provide_context(self).argv[0]} does not exist.")

        if not os.access(provide_context(self).argv[0], os.X_OK):
            raise RuntimeError(
                f"File {provide_context(self).argv[0]} is not executable.",
            )

        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")
            self.kill()

        self.instanced = True

        if not self._polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self._polling_thread_command_queue.put((self.__threaded_run, ()))

        if self.context.escape_antidebug:
            liblog.debugger("Enabling anti-debugging escape mechanism.")
            self._enable_antidebug_escaping()

        self._join_and_check_status()

        if not self.context.pipe_manager:
            raise RuntimeError("Something went wrong during pipe initialization.")

        return self.context.pipe_manager

    def attach(self: _InternalDebugger, pid: int) -> None:
        """Attaches to an existing process."""
        if self.instanced:
            liblog.debugger("Process already running, stopping it before restarting.")

        self.instanced = True

        if not self._polling_thread_command_queue.empty():
            raise RuntimeError("Polling thread command queue not empty.")

        self._polling_thread_command_queue.put((self.__threaded_attach, (pid,)))

        self._join_and_check_status()

    def detach(self: _InternalDebugger) -> None:
        """Detaches from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot detach.")

        self._ensure_process_stopped()

        self._polling_thread_command_queue.put((self.__threaded_detach, ()))

        self._join_and_check_status()

    def _start_processing_thread(self: _InternalDebugger) -> None:
        """Starts the thread that will poll the traced process for state change."""
        # Set as daemon so that the Python interpreter can exit even if the thread is still running
        self._polling_thread = Thread(
            target=self._polling_thread_function,
            name="libdebug_polling_thread",
            daemon=True,
        )
        self._polling_thread.start()

    def _background_ensure_process_stopped(self: _InternalDebugger) -> None:
        """Validates the state of the process."""
        # In background mode, there shouldn't be anything to do here

    def _background_invalid_call(self: _InternalDebugger) -> None:
        """Raises an error when an invalid call is made in background mode."""
        raise RuntimeError("This method is not available in a callback.")

    @background_alias(_background_ensure_process_stopped)
    def _ensure_process_stopped(self: _InternalDebugger) -> None:
        """Validates the state of the process."""
        if not self.instanced:
            raise RuntimeError(
                "Process not running, cannot continue. Did you call run()?",
            )

        if not self.context.running:
            return

        if self.context.auto_interrupt_on_command:
            self.context.interrupt()

        self._join_and_check_status()

    def _threads_are_alive(self: _InternalDebugger) -> bool:
        """Checks if at least one thread is alive."""
        return any(not thread.dead for thread in self.context.threads)

    def _join_and_check_status(self: _InternalDebugger) -> None:
        # Wait for the background thread to signal "task done" before returning
        # We don't want any asynchronous behaviour here
        self._polling_thread_command_queue.join()

        # Check for any exceptions raised by the background thread
        if not self._polling_thread_response_queue.empty():
            response = self._polling_thread_response_queue.get()
            self._polling_thread_response_queue.task_done()
            if response is not None:
                raise response

    @background_alias(_background_invalid_call)
    def kill(self: _InternalDebugger) -> None:
        """Kills the process."""
        try:
            self._ensure_process_stopped()
        except OSError:
            # This exception might occur if the process has already died
            liblog.debugger("OSError raised during kill")

        self._polling_thread_command_queue.put((self.__threaded_kill, ()))

        self.instanced = None

        if self.context.pipe_manager is not None:
            self.context.pipe_manager.close()
            self.context.pipe_manager = None

        self._join_and_check_status()

        self.context.clear()
        self.interface.reset()

    @background_alias(_background_invalid_call)
    @control_flow_function
    def cont(self: _InternalDebugger, auto_wait: bool = True) -> None:
        """Continues the process.

        Args:
            auto_wait (bool, optional): Whether to automatically wait for the process to stop after continuing. Defaults to True.
        """
        self._polling_thread_command_queue.put((self.__threaded_cont, ()))

        self._join_and_check_status()

        if auto_wait:
            self._polling_thread_command_queue.put((self.__threaded_wait, ()))

    @background_alias(_background_invalid_call)
    def interrupt(self: _InternalDebugger) -> None:
        """Interrupts the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot interrupt.")

        if not self.context.running:
            return

        self.context.interrupt()

        self.wait()

    @background_alias(_background_invalid_call)
    def wait(self: _InternalDebugger) -> None:
        """Waits for the process to stop."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot wait.")

        self._join_and_check_status()

        if self.context.dead:
            raise RuntimeError("Process is dead.")

        if not self.context.running:
            # Most of the time the function returns here, as there was a wait already
            # queued by the previous command
            return

        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        self._join_and_check_status()

    def _background_step(self: _InternalDebugger, thread: ThreadContext | None = None) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext, optional): The thread to step. Defaults to None.
        """
        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        self.__threaded_step(thread)
        self.__threaded_wait()

    @background_alias(_background_step)
    @control_flow_function
    def step(self: _InternalDebugger, thread: ThreadContext | None = None) -> None:
        """Executes a single instruction of the process.

        Args:
            thread (ThreadContext, optional): The thread to step. Defaults to None.
        """
        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        self._polling_thread_command_queue.put((self.__threaded_step, (thread,)))
        self._polling_thread_command_queue.put((self.__threaded_wait, ()))

        self._join_and_check_status()

    def _background_step_until(
        self: _InternalDebugger,
        position: int | str,
        thread: ThreadContext | None = None,
        max_steps: int = -1,
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            thread (ThreadContext, optional): The thread to step. Defaults to None.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        if isinstance(position, str):
            address = self.context.resolve_symbol(position)
        else:
            address = self.context.resolve_address(position)

        self.__threaded_step_until(thread, address, max_steps)

    @background_alias(_background_step_until)
    @control_flow_function
    def step_until(
        self: _InternalDebugger,
        position: int | str,
        thread: ThreadContext | None = None,
        max_steps: int = -1,
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            thread (ThreadContext, optional): The thread to step. Defaults to None.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        if isinstance(position, str):
            address = self.context.resolve_symbol(position)
        else:
            address = self.context.resolve_address(position)

        arguments = (
            thread,
            address,
            max_steps,
        )

        self._polling_thread_command_queue.put((self.__threaded_step_until, arguments))

        self._join_and_check_status()

    @background_alias(_background_invalid_call)
    def breakpoint(
        self: _InternalDebugger,
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
            address = self.context.resolve_symbol(position)
        else:
            address = self.context.resolve_address(position)
            position = hex(address)

        if condition:
            if not hardware:
                raise ValueError(
                    "Breakpoint condition is supported only for hardware watchpoints.",
                )

            if condition.lower() not in ["w", "rw", "x"]:
                raise ValueError(
                    "Invalid condition for watchpoints. Supported conditions are 'r', 'rw', 'x'.",
                )

            if length not in [1, 2, 4, 8]:
                raise ValueError(
                    "Invalid length for watchpoints. Supported lengths are 1, 2, 4, 8.",
                )

        if hardware and not condition:
            condition = "x"

        bp = Breakpoint(address, position, 0, hardware, callback, condition, length)

        link_context(bp, self)

        self._polling_thread_command_queue.put((self.__threaded_breakpoint, (bp,)))

        self._join_and_check_status()

        # the breakpoint should have been set by interface
        if address not in self.breakpoints:
            raise RuntimeError("Something went wrong while inserting the breakpoint.")

        return bp

    @background_alias(_background_invalid_call)
    def watchpoint(
        self: _InternalDebugger,
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

    @background_alias(_background_invalid_call)
    def hook_signal(
        self: _InternalDebugger,
        signal_to_hook: int | str,
        callback: None | Callable[[ThreadContext, int], None] = None,
        hook_hijack: bool = True,
    ) -> SignalHook:
        """Hooks a signal in the target process.

        Args:
            signal_to_hook (int | str): The signal to hook.
            callback (Callable[[ThreadContext, int], None], optional): A callback to be called when the signal is received. Defaults to None.
            hook_hijack (bool, optional): Whether to execute the hook/hijack of the new signal after an hijack or not. Defaults to False.
        """
        self._ensure_process_stopped()

        if callback is None:
            raise ValueError("A callback must be specified.")

        if isinstance(signal_to_hook, str):
            signal_number = resolve_signal_number(signal_to_hook)
        elif isinstance(signal_to_hook, int):
            signal_number = signal_to_hook
        else:
            raise TypeError("signal must be an int or a str")

        if signal_number == signal.SIGKILL:
            raise ValueError(
                f"Cannot hook SIGKILL ({signal_number}) as it cannot be caught or ignored. This is a kernel restriction.",
            )
        if signal_number == signal.SIGSTOP:
            raise ValueError(
                f"Cannot hook SIGSTOP ({signal_number}) as it is used by the debugger or ptrace for their internal operations.",
            )
        if signal_number == signal.SIGTRAP:
            raise ValueError(
                f"Cannot hook SIGTRAP ({signal_number}) as it is used by the debugger or ptrace for their internal operations.",
            )

        if signal_number in self.context.signal_hooks:
            liblog.warning(
                f"Signal {resolve_signal_name(signal_number)} ({signal_number}) is already hooked. Overriding it.",
            )
            self.unhook_signal(self.context.signal_hooks[signal_number])

        if not isinstance(hook_hijack, bool):
            raise TypeError("hook_hijack must be a boolean")

        hook = SignalHook(signal_number, callback, hook_hijack)

        link_context(hook, self)

        self._polling_thread_command_queue.put((self.__threaded_signal_hook, (hook,)))

        self._join_and_check_status()

        return hook

    @background_alias(_background_invalid_call)
    def unhook_signal(self: _InternalDebugger, hook: SignalHook) -> None:
        """Unhooks a signal in the target process.

        Args:
            hook (SignalHook): The signal hook to unhook.
        """
        self._ensure_process_stopped()

        if hook.signal_number not in self.context.signal_hooks:
            raise ValueError(f"Signal {hook.signal_number} is not hooked.")

        hook = self.context.signal_hooks[hook.signal_number]

        self._polling_thread_command_queue.put((self.__threaded_signal_unhook, (hook,)))

        self._join_and_check_status()

    @background_alias(_background_invalid_call)
    def hijack_signal(
        self: _InternalDebugger,
        original_signal: int | str,
        new_signal: int | str,
        hook_hijack: bool = True,
    ) -> None:
        """Hijacks a signal in the target process.

        Args:
            original_signal (int | str): The signal to hijack.
            new_signal (int | str): The signal to replace the original signal with.
            hook_hijack (bool, optional): Whether to execute the hook/hijack of the new signal after the hijack or not. Defaults to True.
        """
        self._ensure_process_stopped()

        if isinstance(original_signal, str):
            original_signal_number = resolve_signal_number(original_signal)
        else:
            original_signal_number = original_signal

        new_signal_number = resolve_signal_number(new_signal) if isinstance(new_signal, str) else new_signal

        if original_signal_number == new_signal_number:
            raise ValueError(
                "The original signal and the new signal must be different during hijacking.",
            )

        def callback(thread: ThreadContext, _: int) -> None:
            """The callback to execute when the signal is received."""
            thread.signal_number = new_signal_number

        return self.hook_signal(original_signal_number, callback, hook_hijack)

    def _enable_pretty_print(
        self: _InternalDebugger,
    ) -> SyscallHook:
        """Hooks a syscall in the target process to pretty prints its arguments and return value."""
        self._ensure_process_stopped()

        syscall_numbers = get_all_syscall_numbers()

        for syscall_number in syscall_numbers:
            # Check if the syscall is already hooked (by the user or by the pretty print hook)
            if syscall_number in self.context.syscall_hooks:
                hook = self.context.syscall_hooks[syscall_number]
                if syscall_number not in (self.context._syscalls_to_not_pprint or []) and syscall_number in (
                    self.context._syscalls_to_pprint or syscall_numbers
                ):
                    hook.on_enter_pprint = pprint_on_enter
                    hook.on_exit_pprint = pprint_on_exit
                else:
                    # Remove the pretty print hook from previous pretty print calls
                    hook.on_enter_pprint = None
                    hook.on_exit_pprint = None
            elif syscall_number not in (self.context._syscalls_to_not_pprint or []) and syscall_number in (
                self.context._syscalls_to_pprint or syscall_numbers
            ):
                hook = SyscallHook(
                    syscall_number,
                    None,
                    None,
                    pprint_on_enter,
                    pprint_on_exit,
                )

                link_context(hook, self)

                self._polling_thread_command_queue.put(
                    (self.__threaded_syscall_hook, (hook,)),
                )

        self._join_and_check_status()

    def _disable_pretty_print(self: _InternalDebugger) -> None:
        """Unhooks all syscalls that are pretty printed."""
        self._ensure_process_stopped()

        installed_hooks = list(self.context.syscall_hooks.values())
        for hook in installed_hooks:
            if hook.on_enter_pprint or hook.on_exit_pprint:
                if hook.on_enter_user or hook.on_exit_user:
                    hook.on_enter_pprint = None
                    hook.on_exit_pprint = None
                else:
                    self._polling_thread_command_queue.put(
                        (self.__threaded_syscall_unhook, (hook,)),
                    )
        self._join_and_check_status()

    def _enable_antidebug_escaping(self: _InternalDebugger) -> None:
        """Enables the anti-debugging escape mechanism."""
        hook = SyscallHook(
            resolve_syscall_number("ptrace"),
            on_enter_ptrace,
            on_exit_ptrace,
            None,
            None,
        )

        link_context(hook, self)

        self._polling_thread_command_queue.put((self.__threaded_syscall_hook, (hook,)))

        # setup hidden state for the hook
        hook._traceme_called = False
        hook._command = None

    @background_alias(_background_invalid_call)
    def hook_syscall(
        self: _InternalDebugger,
        syscall: int | str,
        on_enter: Callable[[ThreadContext, int], None] | None = None,
        on_exit: Callable[[ThreadContext, int], None] | None = None,
        hook_hijack: bool = True,
    ) -> SyscallHook:
        """Hooks a syscall in the target process.

        Args:
            syscall (int | str): The syscall name or number to hook.
            on_enter (Callable[[ThreadContext, int], None], optional): The callback to execute when the syscall is entered. Defaults to None.
            on_exit (Callable[[ThreadContext, int], None], optional): The callback to execute when the syscall is exited. Defaults to None.
            hook_hijack (bool, optional): Whether the syscall after the hijack should be hooked. Defaults to True.

        Returns:
            SyscallHook: The syscall hook object.
        """
        self._ensure_process_stopped()

        if on_enter is None and on_exit is None:
            raise ValueError(
                "At least one callback between on_enter and on_exit should be specified.",
            )

        syscall_number = resolve_syscall_number(syscall) if isinstance(syscall, str) else syscall

        if not isinstance(hook_hijack, bool):
            raise TypeError("hook_hijack must be a boolean")

        # Check if the syscall is already hooked (by the user or by the pretty print hook)
        if syscall_number in self.context.syscall_hooks:
            hook = self.context.syscall_hooks[syscall_number]
            if hook.on_enter_user or hook.on_exit_user:
                liblog.warning(
                    f"Syscall {resolve_syscall_name(syscall_number)} is already hooked by a user-defined hook. Overriding it.",
                )
            hook.on_enter_user = on_enter
            hook.on_exit_user = on_exit
            hook.hook_hijack = hook_hijack
            hook.enabled = True
        else:
            hook = SyscallHook(
                syscall_number,
                on_enter,
                on_exit,
                None,
                None,
                hook_hijack,
            )

            link_context(hook, self)

            self._polling_thread_command_queue.put(
                (self.__threaded_syscall_hook, (hook,)),
            )

            self._join_and_check_status()

        return hook

    @background_alias(_background_invalid_call)
    def unhook_syscall(self: _InternalDebugger, hook: SyscallHook) -> None:
        """Unhooks a syscall in the target process.

        Args:
            hook (SyscallHook): The syscall hook to unhook.
        """
        self._ensure_process_stopped()

        if hook.syscall_number not in self.context.syscall_hooks:
            raise ValueError(f"Syscall {hook.syscall_number} is not hooked.")

        hook = self.context.syscall_hooks[hook.syscall_number]

        if hook.on_enter_pprint or hook.on_exit_pprint:
            hook.on_enter_user = None
            hook.on_exit_user = None
        else:
            self._polling_thread_command_queue.put(
                (self.__threaded_syscall_unhook, (hook,)),
            )

            self._join_and_check_status()

    @background_alias(_background_invalid_call)
    def hijack_syscall(
        self: _InternalDebugger,
        original_syscall: int | str,
        new_syscall: int | str,
        hook_hijack: bool = True,
        **kwargs: int,
    ) -> SyscallHook:
        """Hijacks a syscall in the target process.

        Args:
            original_syscall (int | str): The syscall name or number to hijack.
            new_syscall (int | str): The syscall name or number to replace the original syscall with.
            hook_hijack (bool, optional): Whether the syscall after the hijack should be hooked. Defaults to True.
            **kwargs: (int, optional): The arguments to pass to the new syscall.

        Returns:
            SyscallHook: The syscall hook object.
        """
        self._ensure_process_stopped()

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

        # Check if the syscall is already hooked (by the user or by the pretty print hook)
        if original_syscall_number in self.context.syscall_hooks:
            hook = self.context.syscall_hooks[original_syscall_number]
            if hook.on_enter_user or hook.on_exit_user:
                liblog.warning(
                    f"Syscall {original_syscall_number} is already hooked by a user-defined hook. Overriding it.",
                )
            hook.on_enter_user = on_enter
            hook.on_exit_user = None
            hook.hook_hijack = hook_hijack
            hook.enabled = True
        else:
            hook = SyscallHook(
                original_syscall_number,
                on_enter,
                None,
                None,
                None,
                hook_hijack,
            )

            link_context(hook, self)

            self._polling_thread_command_queue.put(
                (self.__threaded_syscall_hook, (hook,)),
            )

            self._join_and_check_status()

        return hook

    @property
    def pprint_syscalls(self: _InternalDebugger) -> bool:
        """Get the state of the pprint_syscalls flag.

        Returns:
            bool: True if the debugger should pretty print syscalls, False otherwise.
        """
        return self.context._pprint_syscalls

    @pprint_syscalls.setter
    def pprint_syscalls(self: _InternalDebugger, value: bool) -> None:
        """Set the state of the pprint_syscalls flag.

        Args:
            value (bool): the value to set.
        """
        if not isinstance(value, bool):
            raise TypeError("pprint_syscalls must be a boolean")

        if value:
            self._enable_pretty_print()
        else:
            self._disable_pretty_print()

        self.context._pprint_syscalls = value

    @contextmanager
    def pprint_syscalls_context(self: _InternalDebugger, value: bool) -> ...:
        """A context manager to temporarily change the state of the pprint_syscalls flag.

        Args:
            value (bool): the value to set.

        Yields:
            None
        """
        old_value = self.pprint_syscalls
        self.pprint_syscalls = value
        yield
        self.pprint_syscalls = old_value

    @property
    def syscalls_to_pprint(self: _InternalDebugger) -> list[str] | None:
        """Get the syscalls to pretty print.

        Returns:
            list[str]: The syscalls to pretty print.
        """
        if self.context._syscalls_to_pprint is None:
            return None
        else:
            return [resolve_syscall_name(v) for v in self.context._syscalls_to_pprint]

    @syscalls_to_pprint.setter
    def syscalls_to_pprint(self: _InternalDebugger, value: list[int] | list[str] | None) -> None:
        """Get the syscalls to pretty print.

        Args:
            value (list[int] | list[str] | None): The syscalls to pretty print.
        """
        if value is None:
            self.context._syscalls_to_pprint = None
        elif isinstance(value, list):
            self.context._syscalls_to_pprint = [v if isinstance(v, int) else resolve_syscall_number(v) for v in value]
        else:
            raise ValueError(
                "syscalls_to_pprint must be a list of integers or strings or None.",
            )
        if self.context._pprint_syscalls:
            self._enable_pretty_print()

    @property
    def syscalls_to_not_pprint(self: _InternalDebugger) -> list[str] | None:
        """Get the syscalls to not pretty print.

        Returns:
            list[str]: The syscalls to not pretty print.
        """
        if self.context._syscalls_to_not_pprint is None:
            return None
        else:
            return [resolve_syscall_name(v) for v in self.context._syscalls_to_not_pprint]

    @syscalls_to_not_pprint.setter
    def syscalls_to_not_pprint(self: _InternalDebugger, value: list[int] | list[str] | None) -> None:
        """Get the syscalls to not pretty print.

        Args:
            value (list[int] | list[str] | None): The syscalls to not pretty print.
        """
        if value is None:
            self.context._syscalls_to_not_pprint = None
        elif isinstance(value, list):
            self.context._syscalls_to_not_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_not_pprint must be a list of integers or strings or None.",
            )
        if self.context._pprint_syscalls:
            self._enable_pretty_print()

    @property
    def signal_to_block(self: _InternalDebugger) -> list[str]:
        """Get the signal to not forward to the process.

        Returns:
            list[str]: The signals to block.
        """
        return [resolve_signal_name(v) for v in self.context._signal_to_block]

    @signal_to_block.setter
    def signal_to_block(self: _InternalDebugger, signals: list[int] | list[str]) -> None:
        """Set the signal to not forward to the process.

        Args:
            signals (list[int] | list[str]): The signals to block.
        """
        if not isinstance(signals, list):
            raise TypeError("signal_to_block must be a list of integers or strings")

        signals = [v if isinstance(v, int) else resolve_signal_number(v) for v in signals]

        if not set(signals).issubset(get_all_signal_numbers()):
            raise ValueError("Invalid signal number.")

        self.context._signal_to_block = signals

    @background_alias(_background_invalid_call)
    def migrate_to_gdb(self: _InternalDebugger, open_in_new_process: bool = True) -> None:
        """Migrates the current debugging session to GDB."""
        self._ensure_process_stopped()

        self.context.interrupt()

        self._polling_thread_command_queue.put((self.__threaded_migrate_to_gdb, ()))

        self._join_and_check_status()

        if open_in_new_process and libcontext.terminal:
            self._open_gdb_in_new_process()
        else:
            if open_in_new_process:
                liblog.warning(
                    "Cannot open in a new process. Please configure the terminal in libcontext.terminal.",
                )
            self._open_gdb_in_shell()

        self._polling_thread_command_queue.put((self.__threaded_migrate_from_gdb, ()))

        self._join_and_check_status()

        # We have to ignore a SIGSTOP signal that is sent by GDB
        # TODO: once we have signal handling, we should remove this
        self.step()

    def _background_finish(
        self: _InternalDebugger,
        thread: ThreadContext | None = None,
        exact: bool = True,
    ) -> None:
        """Continues the process until the current function returns or the process stops.

        When used in step mode, it will step until a return instruction is executed. Otherwise, it uses a heuristic
        based on the call stack to breakpoint (exact is slower).

        Args:
            thread (ThreadContext, optional): The thread to affect. Defaults to None.
            exact (bool, optional): Whether or not to execute in step mode. Defaults to True.
        """
        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        self.__threaded_finish(thread, exact)

    @background_alias(_background_finish)
    def finish(self: _InternalDebugger, thread: ThreadContext | None = None, exact: bool = True) -> None:
        """Continues the process until the current function returns or the process stops.

        When used in step mode, it will step until a return instruction is executed. Otherwise, it uses a heuristic
        based on the call stack to breakpoint (exact is slower).

        Args:
            thread (ThreadContext, optional): The thread to affect. Defaults to None.
            exact (bool, optional): Whether or not to execute in step mode. Defaults to True.
        """
        self._ensure_process_stopped()

        if thread is None:
            # If no thread is specified, we use the first thread
            thread = self.threads[0]

        self._polling_thread_command_queue.put(
            (self.__threaded_finish, (thread, exact)),
        )

        self._join_and_check_status()

    def _craft_gdb_migration_command(self: _InternalDebugger) -> list[str]:
        """Crafts the command to migrate to GDB."""
        gdb_command = [
            "/bin/gdb",
            "-q",
            "--pid",
            str(self.context.process_id),
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

                if self.instruction_pointer == bp.address:
                    # We have to enqueue an additional continue
                    bp_args.append("-ex")
                    bp_args.append("ni")

        return gdb_command + bp_args

    def _open_gdb_in_new_process(self: _InternalDebugger) -> None:
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

    def _open_gdb_in_shell(self: _InternalDebugger) -> None:
        """Open GDB in the current shell."""
        gdb_pid = os.fork()
        if gdb_pid == 0:  # This is the child process.
            args = self._craft_gdb_migration_command()
            os.execv("/bin/gdb", args)
        else:  # This is the parent process.
            os.waitpid(gdb_pid, 0)  # Wait for the child process to finish.

    def __getattr__(self: _InternalDebugger, name: str) -> object:
        """This function is called when an attribute is not found in the `_InternalDebugger` object.

        It is used to forward the call to the first `ThreadContext` object.
        """
        if not self.threads:
            raise AttributeError(f"'debugger has no attribute '{name}'")

        self._ensure_process_stopped()

        thread_context = self.threads[0]

        if not hasattr(thread_context, name):
            raise AttributeError(f"'debugger has no attribute '{name}'")

        return getattr(thread_context, name)

    def __setattr__(self: _InternalDebugger, name: str, value: object) -> None:
        """This function is called when an attribute is set in the `_InternalDebugger` object.

        It is used to forward the call to the first `ThreadContext` object.
        """
        # First we check if the attribute is available in the `_InternalDebugger` object
        if hasattr(_InternalDebugger, name):
            super().__setattr__(name, value)
        else:
            self._ensure_process_stopped()
            thread_context = self.threads[0]
            setattr(thread_context, name, value)

    def __threaded_peek_memory(self: _InternalDebugger, address: int) -> bytes | BaseException:
        try:
            value = self.interface.peek_memory(address)
            # TODO: this is only for amd64
            return value.to_bytes(8, "little")
        except BaseException as e:
            return e

    def __threaded_poke_memory(self: _InternalDebugger, address: int, data: bytes) -> None:
        int_data = int.from_bytes(data, "little")
        self.interface.poke_memory(address, int_data)

    @background_alias(__threaded_peek_memory)
    def _peek_memory(self: _InternalDebugger, address: int) -> bytes:
        """Reads memory from the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if self.context.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before reading memory.",
            )

        self._ensure_process_stopped()

        self._polling_thread_command_queue.put(
            (self.__threaded_peek_memory, (address,)),
        )

        # We cannot call _join_and_check_status here, as we need the return value which might not be an exception
        self._polling_thread_command_queue.join()

        value = self._polling_thread_response_queue.get()
        self._polling_thread_response_queue.task_done()

        if isinstance(value, BaseException):
            raise value

        return value

    @background_alias(__threaded_poke_memory)
    def _poke_memory(self: _InternalDebugger, address: int, data: bytes) -> None:
        """Writes memory to the process."""
        if not self.instanced:
            raise RuntimeError("Process not running, cannot step.")

        if self.context.running:
            # Reading memory while the process is running could lead to concurrency issues
            # and corrupted values
            liblog.debugger(
                "Process is running. Waiting for it to stop before writing to memory.",
            )

        self._ensure_process_stopped()

        self._polling_thread_command_queue.put(
            (self.__threaded_poke_memory, (address, data)),
        )

        self._join_and_check_status()

    def _setup_memory_view(self: _InternalDebugger) -> None:
        """Sets up the memory view of the process."""
        with context_extend_from(self):
            self.memory = MemoryView(self._peek_memory, self._poke_memory)

        self.context.memory = self.memory

    def _is_in_background(self: _InternalDebugger) -> None:
        return current_thread() == self._polling_thread

    def _polling_thread_function(self: _InternalDebugger) -> None:
        """This function is run in a thread. It is used to poll the process for state change."""
        while True:
            # Wait for the main thread to signal a command to execute
            command, args = self._polling_thread_command_queue.get()

            if command == THREAD_TERMINATE:
                # Signal that the command has been executed
                self._polling_thread_command_queue.task_done()
                return

            # Execute the command
            try:
                return_value = command(*args)
            except BaseException as e:
                return_value = e

            if return_value is not None:
                self._polling_thread_response_queue.put(return_value)

            # Signal that the command has been executed
            self._polling_thread_command_queue.task_done()

            if return_value is not None:
                self._polling_thread_response_queue.join()

    def __threaded_run(self: _InternalDebugger) -> None:
        liblog.debugger("Starting process %s.", self.context.argv[0])
        self.interface.run()

        self.context.set_stopped()

    def __threaded_attach(self: _InternalDebugger, pid: int) -> None:
        liblog.debugger("Attaching to process %d.", pid)
        self.interface.attach(pid)

        self.context.set_stopped()

    def __threaded_detach(self: _InternalDebugger) -> None:
        liblog.debugger("Detaching from process %d.", self.context.process_id)
        self.interface.detach()

        self.context.set_stopped()

    def __threaded_kill(self: _InternalDebugger) -> None:
        if self.context.argv:
            liblog.debugger(
                "Killing process %s (%d).",
                self.context.argv[0],
                self.context.process_id,
            )
        else:
            liblog.debugger("Killing process %d.", self.context.process_id)
        self.interface.kill()

    def __threaded_cont(self: _InternalDebugger) -> None:
        if self.context.argv:
            liblog.debugger(
                "Continuing process %s (%d).",
                self.context.argv[0],
                self.context.process_id,
            )
        else:
            liblog.debugger("Continuing process %d.", self.context.process_id)

        self.interface.cont()
        self.context.set_running()

    def __threaded_breakpoint(self: _InternalDebugger, bp: Breakpoint) -> None:
        liblog.debugger("Setting breakpoint at 0x%x.", bp.address)
        self.interface.set_breakpoint(bp)

    def __threaded_syscall_hook(self: _InternalDebugger, hook: SyscallHook) -> None:
        liblog.debugger(f"Hooking syscall {hook.syscall_number}.")
        self.interface.set_syscall_hook(hook)

    def __threaded_signal_hook(self: _InternalDebugger, hook: SignalHook) -> None:
        liblog.debugger(
            f"Hooking signal {resolve_signal_name(hook.signal_number)} ({hook.signal_number}).",
        )
        self.interface.set_signal_hook(hook)

    def __threaded_syscall_unhook(self: _InternalDebugger, hook: SyscallHook) -> None:
        liblog.debugger(f"Unhooking syscall {hook.syscall_number}.")
        self.interface.unset_syscall_hook(hook)

    def __threaded_signal_unhook(self: _InternalDebugger, hook: SignalHook) -> None:
        liblog.debugger(f"Unhooking syscall {hook.signal_number}.")
        self.interface.unset_signal_hook(hook)

    def __threaded_wait(self: _InternalDebugger) -> None:
        if self.context.argv:
            liblog.debugger(
                "Waiting for process %s (%d) to stop.",
                self.context.argv[0],
                self.context.process_id,
            )
        else:
            liblog.debugger("Waiting for process %d to stop.", self.context.process_id)

        while True:
            if not self._threads_are_alive():
                # All threads are dead
                liblog.debugger("All threads dead")
                break
            self.context._resume_context.resume = ResumeStatus.UNDECIDED
            self.interface.wait()
            match self.context._resume_context.resume:
                case ResumeStatus.RESUME:
                    self.interface.cont()
                case ResumeStatus.NOT_RESUME:
                    break
                case ResumeStatus.UNDECIDED:
                    if self.context.force_continue:
                        liblog.warning(
                            "Stop due to unhandled signal. Trying to continue.",
                        )
                        self.interface.cont()
                    else:
                        liblog.warning("Stop due to unhandled signal. Hanging.")
                        break

        self.context.set_stopped()

    def __threaded_step(self: _InternalDebugger, thread: ThreadContext) -> None:
        liblog.debugger("Stepping thread %s.", thread.thread_id)
        self.interface.step(thread)
        self.context.set_running()

    def __threaded_step_until(
        self: _InternalDebugger,
        thread: ThreadContext,
        address: int,
        max_steps: int,
    ) -> None:
        liblog.debugger("Stepping thread %s until 0x%x.", thread.thread_id, address)
        self.interface.step_until(thread, address, max_steps)
        self.context.set_stopped()

    def __threaded_finish(self: _InternalDebugger, thread: ThreadContext, exact: bool) -> None:
        prefix = "Exact" if exact else "Heuristic"

        liblog.debugger(f"{prefix} finish on thread %s", thread.thread_id)
        self.interface.finish(thread, exact=exact)

        self.context.set_stopped()

    def __threaded_migrate_to_gdb(self: _InternalDebugger) -> None:
        self.interface.migrate_to_gdb()

    def __threaded_migrate_from_gdb(self: _InternalDebugger) -> None:
        self.interface.migrate_from_gdb()


def debugger(
    argv: str | list[str] = [],
    enable_aslr: bool = False,
    env: dict[str, str] | None = None,
    escape_antidebug: bool = False,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = False,
    force_continue: bool = True,
) -> _InternalDebugger:
    """This function is used to create a new `_InternalDebugger` object. It takes as input the location of the binary to debug and returns a `_InternalDebugger` object.

    Args:
        argv (str | list[str], optional): The location of the binary to debug, and any additional arguments to pass to it.
        enable_aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        escape_antidebug (bool): Whether to automatically attempt to patch antidebugger detectors based on the ptrace syscall.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to False.
        force_continue (bool, optional): Whether to force the process to continue after an unhandled signal is received. Defaults to True.

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
    debugging_context.escape_antidebug = escape_antidebug
    debugging_context.force_continue = force_continue

    debugger._post_init_()

    return debugger
