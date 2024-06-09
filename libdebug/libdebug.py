#
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import TYPE_CHECKING

from libdebug.data.breakpoint import Breakpoint
from libdebug.data.memory_view import MemoryView
from libdebug.data.signal_hook import SignalHook
from libdebug.data.syscall_hook import SyscallHook
from libdebug.data.thread_list import ThreadList
from libdebug.interfaces.interface_helper import provide_debugging_interface
from libdebug.state.debugging_context import (
    DebuggingContext,
    context_extend_from,
    create_context,
    provide_context,
)
from libdebug.utils.signal_utils import (
    get_all_signal_numbers,
    resolve_signal_name,
    resolve_signal_number,
)
from libdebug.utils.syscall_utils import (
    resolve_syscall_name,
    resolve_syscall_number,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


class _InternalDebugger:
    """The _InternalDebugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    memory: MemoryView | None = None
    """The memory view of the process."""

    _threads: list[ThreadContext] = None
    """A list of all the threads in the process."""

    breakpoints: dict[int, Breakpoint] = None
    """A dictionary of all the breakpoints set on the process. The keys are the absolute addresses of the breakpoints."""

    _context: DebuggingContext | None = None
    """The debugging context of the process."""

    _sentinel: object = object()
    """A sentinel object."""

    def __init__(self: _InternalDebugger) -> None:
        pass

    def _post_init_(self: _InternalDebugger) -> None:
        """Do not use this constructor directly. Use the `debugger` function instead."""
        self._context = provide_context(self)

        with context_extend_from(self):
            self._context.debugging_interface = provide_debugging_interface()

        self._threads = self._context.threads
        self.breakpoints = self._context.breakpoints

        self._context._start_processing_thread()
        with context_extend_from(self):
            self._context.setup_memory_view()
        self.memory = self._context.memory

    def terminate(self: _InternalDebugger) -> None:
        """Terminates the background thread.

        The debugger object cannot be used after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        self._context.terminate()

    def run(self: _InternalDebugger) -> None:
        """Starts the process and waits for it to stop."""
        return self._context.run()

    def attach(self: _InternalDebugger, pid: int) -> None:
        """Attaches to an existing process."""
        self._context.attach(pid)

    def detach(self: _InternalDebugger) -> None:
        """Detaches from the process."""
        self._context.detach()

    def kill(self: _InternalDebugger) -> None:
        """Kills the process."""
        self._context.kill()

    def cont(self: _InternalDebugger, auto_wait: bool = True) -> None:
        """Continues the process.

        Args:
            auto_wait (bool, optional): Whether to automatically wait for the process to stop after continuing. Defaults to True.
        """
        self._context.cont(auto_wait)

    def interrupt(self: _InternalDebugger) -> None:
        """Interrupts the process."""
        self._context.interrupt()

    def wait(self: _InternalDebugger) -> None:
        """Waits for the process to stop."""
        self._context.wait()

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
        with context_extend_from(self):
            return self._context.breakpoint(
                position, hardware, condition, length, callback
            )

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
        with context_extend_from(self):
            return self._context.breakpoint(
                position,
                hardware=True,
                condition=condition,
                length=length,
                callback=callback,
            )

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
        with context_extend_from(self):
            return self._context.hook_signal(signal_to_hook, callback, hook_hijack)

    def unhook_signal(self: _InternalDebugger, hook: SignalHook) -> None:
        """Unhooks a signal in the target process.

        Args:
            hook (SignalHook): The signal hook to unhook.
        """
        self._context.unhook_signal(hook)

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
        with context_extend_from(self):
            return self._context.hijack_signal(original_signal, new_signal, hook_hijack)

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
        with context_extend_from(self):
            return self._context.hook_syscall(syscall, on_enter, on_exit, hook_hijack)

    def unhook_syscall(self: _InternalDebugger, hook: SyscallHook) -> None:
        """Unhooks a syscall in the target process.

        Args:
            hook (SyscallHook): The syscall hook to unhook.
        """
        self._context.unhook_syscall(hook)

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
        with context_extend_from(self):
            return self._context.hijack_syscall(
                original_syscall, new_syscall, hook_hijack, **kwargs
            )

    @property
    def pprint_syscalls(self: _InternalDebugger) -> bool:
        """Get the state of the pprint_syscalls flag.

        Returns:
            bool: True if the debugger should pretty print syscalls, False otherwise.
        """
        with context_extend_from(self):
            return self._context._pprint_syscalls

    @pprint_syscalls.setter
    def pprint_syscalls(self: _InternalDebugger, value: bool) -> None:
        """Set the state of the pprint_syscalls flag.

        Args:
            value (bool): the value to set.
        """
        if not isinstance(value, bool):
            raise TypeError("pprint_syscalls must be a boolean")

        if value:
            with context_extend_from(self):
                self._context.enable_pretty_print()
        else:
            with context_extend_from(self):
                self._context.disable_pretty_print()

        self._context._pprint_syscalls = value

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
        if self._context.syscalls_to_pprint is None:
            return None
        else:
            return [resolve_syscall_name(v) for v in self._context.syscalls_to_pprint]

    @syscalls_to_pprint.setter
    def syscalls_to_pprint(
        self: _InternalDebugger, value: list[int] | list[str] | None
    ) -> None:
        """Get the syscalls to pretty print.

        Args:
            value (list[int] | list[str] | None): The syscalls to pretty print.
        """
        if value is None:
            self._context.syscalls_to_pprint = None
        elif isinstance(value, list):
            self._context.syscalls_to_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_pprint must be a list of integers or strings or None.",
            )
        if self._context._pprint_syscalls:
            with context_extend_from(self):
                self._context.enable_pretty_print()

    @property
    def syscalls_to_not_pprint(self: _InternalDebugger) -> list[str] | None:
        """Get the syscalls to not pretty print.

        Returns:
            list[str]: The syscalls to not pretty print.
        """
        if self._context.syscalls_to_not_pprint is None:
            return None
        else:
            return [
                resolve_syscall_name(v) for v in self._context.syscalls_to_not_pprint
            ]

    @syscalls_to_not_pprint.setter
    def syscalls_to_not_pprint(
        self: _InternalDebugger, value: list[int] | list[str] | None
    ) -> None:
        """Get the syscalls to not pretty print.

        Args:
            value (list[int] | list[str] | None): The syscalls to not pretty print.
        """
        if value is None:
            self._context.syscalls_to_not_pprint = None
        elif isinstance(value, list):
            self._context.syscalls_to_not_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_not_pprint must be a list of integers or strings or None.",
            )
        if self._context._pprint_syscalls:
            with context_extend_from(self):
                self._context.enable_pretty_print()

    @property
    def signal_to_block(self: _InternalDebugger) -> list[str]:
        """Get the signal to not forward to the process.

        Returns:
            list[str]: The signals to block.
        """
        return [resolve_signal_name(v) for v in self._context._signal_to_block]

    @signal_to_block.setter
    def signal_to_block(
        self: _InternalDebugger, signals: list[int] | list[str]
    ) -> None:
        """Set the signal to not forward to the process.

        Args:
            signals (list[int] | list[str]): The signals to block.
        """
        if not isinstance(signals, list):
            raise TypeError("signal_to_block must be a list of integers or strings")

        signals = [
            v if isinstance(v, int) else resolve_signal_number(v) for v in signals
        ]

        if not set(signals).issubset(get_all_signal_numbers()):
            raise ValueError("Invalid signal number.")

        self._context._signal_to_block = signals

    @property
    def threads(self: _InternalDebugger) -> ThreadList:
        """Get the list of threads in the process."""
        return self._threads

    @property
    def process_id(self: _InternalDebugger) -> int:
        """Get the process ID of the process."""
        return self._context.process_id

    @property
    def pid(self: _InternalDebugger) -> int:
        """Get the process ID of the process."""
        return self._context.process_id

    def migrate_to_gdb(
        self: _InternalDebugger, open_in_new_process: bool = True
    ) -> None:
        """Migrates the current debugging session to GDB."""
        self._context.migrate_to_gdb(open_in_new_process)

    def finish(
        self: _InternalDebugger, thread: ThreadContext | None = None, exact: bool = True
    ) -> None:
        """Continues the process until the current function returns or the process stops.

        When used in step mode, it will step until a return instruction is executed. Otherwise, it uses a heuristic
        based on the call stack to breakpoint (exact is slower).

        Args:
            thread (ThreadContext, optional): The thread to affect. Defaults to None.
            exact (bool, optional): Whether or not to execute in step mode. Defaults to True.
        """
        self._context.finish(thread, exact)

    def __getattr__(self: _InternalDebugger, name: str) -> object:
        """This function is called when an attribute is not found in the `_InternalDebugger` object.

        It is used to forward the call to the first `ThreadContext` object.
        """
        if not self.threads:
            raise AttributeError(f"'debugger has no attribute '{name}'")

        thread_context = self.threads[0]

        # hasattr internally calls getattr, so we use this to avoid double access to the attribute
        # do not use None as default value, as it is a valid value
        if (attr := getattr(thread_context, name, self._sentinel)) == self._sentinel:
            raise AttributeError(f"'Debugger has no attribute '{name}'")
        return attr

    def __setattr__(self: _InternalDebugger, name: str, value: object) -> None:
        """This function is called when an attribute is set in the `_InternalDebugger` object.

        It is used to forward the call to the first `ThreadContext` object.
        """
        # First we check if the attribute is available in the `_InternalDebugger` object
        if hasattr(_InternalDebugger, name):
            super().__setattr__(name, value)
        else:
            self._context._ensure_process_stopped()
            thread_context = self.threads[0]
            setattr(thread_context, name, value)


def debugger(
    argv: str | list[str] = [],
    enable_aslr: bool = False,
    env: dict[str, str] | None = None,
    escape_antidebug: bool = False,
    continue_to_binary_entrypoint: bool = True,
    auto_interrupt_on_command: bool = False,
) -> _InternalDebugger:
    """This function is used to create a new `_InternalDebugger` object. It takes as input the location of the binary to debug and returns a `_InternalDebugger` object.

    Args:
        argv (str | list[str], optional): The location of the binary to debug, and any additional arguments to pass to it.
        enable_aslr (bool, optional): Whether to enable ASLR. Defaults to False.
        env (dict[str, str], optional): The environment variables to use. Defaults to the same environment of the debugging script.
        escape_antidebug (bool): Whether to automatically attempt to patch antidebugger detectors based on the ptrace syscall.
        continue_to_binary_entrypoint (bool, optional): Whether to automatically continue to the binary entrypoint. Defaults to True.
        auto_interrupt_on_command (bool, optional): Whether to automatically interrupt the process when a command is issued. Defaults to False.

    Returns:
        _InternalDebugger: The `_InternalDebugger` object.
    """
    if isinstance(argv, str):
        argv = [argv]

    debugger = _InternalDebugger()

    debugging_context = create_context(debugger)

    if not env:
        env = os.environ

    debugging_context.argv = argv
    debugging_context.env = env
    debugging_context.aslr_enabled = enable_aslr
    debugging_context.autoreach_entrypoint = continue_to_binary_entrypoint
    debugging_context.auto_interrupt_on_command = auto_interrupt_on_command
    debugging_context.escape_antidebug = escape_antidebug

    debugger._post_init_()

    return debugger
