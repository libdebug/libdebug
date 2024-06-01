#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import signal
from contextlib import contextmanager
from threading import Lock
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from libdebug.state.resume_context import ResumeContext
from libdebug.utils.debugging_utils import (
    normalize_and_validate_address,
    resolve_symbol_in_maps,
)

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.memory_view import MemoryView
    from libdebug.data.signal_hook import SignalHook
    from libdebug.data.syscall_hook import SyscallHook
    from libdebug.interfaces.debugging_interface import DebuggingInterface
    from libdebug.state.thread_context import ThreadContext
    from libdebug.utils.pipe_manager import PipeManager


class DebuggingContext:
    """A class that holds the global debugging state."""

    _instance = None

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

    force_continue: bool
    """A flag that indicates if the debugger should force the debugged process to continue after an unhandled signal is received."""

    _breakpoints: dict[int, Breakpoint]
    """A dictionary of all the breakpoints set on the process.
    Key: the address of the breakpoint."""

    _syscall_hooks: dict[int, SyscallHook]
    """A dictionary of all the syscall hooks set on the process.
    Key: the syscall number."""

    _signal_hooks: dict[int, SignalHook]
    """A dictionary of all the signal hooks set on the process.
    Key: the signal number."""

    _signal_to_pass: list[int]
    """The signals to pass to the process."""

    _syscalls_to_pprint: list[int] | None
    """The syscalls to pretty print."""

    _syscalls_to_not_pprint: list[int] | None
    """The syscalls to not pretty print."""

    _threads: list[ThreadContext]
    """A list of all the threads of the debugged process."""

    pipe_manager: PipeManager
    """The pipe manager used to communicate with the debugged process."""

    _is_running: bool
    """The overall state of the debugged process. True if the process is running, False otherwise."""

    process_id: int
    """The PID of the debugged process."""

    debugging_interface: DebuggingInterface
    """The debugging interface used to communicate with the debugged process."""

    memory: MemoryView
    """The memory view of the debugged process."""

    _pprint_syscalls: bool
    """A flag that indicates if the debugger should pretty print syscalls."""

    _resume_context: ResumeContext
    """Context that indicates if the debugger should resume the debugged process."""

    def __init__(self: DebuggingContext) -> None:
        """Initialize the context."""
        # These must be reinitialized on every call to "debugger"
        self.aslr_enabled = False
        self.autoreach_entrypoint = True
        self.argv = []
        self.env = {}
        self.escape_antidebug = False
        self._breakpoints = {}
        self._syscall_hooks = {}
        self._signal_hooks = {}
        self._signal_to_pass = []
        self._syscalls_to_pprint = None
        self._syscalls_to_not_pprint = None
        self._threads = []
        self._pprint_syscalls = False
        self._resume_context = ResumeContext()
        self.clear()

    def clear(self: DebuggingContext) -> None:
        """Reinitializes the context, so it is ready for a new run."""
        # These must be reinitialized on every call to "run"
        self._breakpoints.clear()
        self._syscall_hooks.clear()
        self._signal_hooks.clear()
        self._threads.clear()
        self.pipe_manager = None
        self._is_running = False
        self._syscalls_to_pprint = None
        self._syscalls_to_not_pprint = None
        self._signal_to_pass.clear()
        self.process_id = 0
        self._resume_context = ResumeContext()

    @property
    def breakpoints(self: DebuggingContext) -> dict[int, Breakpoint]:
        """Get the breakpoints dictionary.

        Returns:
            dict[int, Breakpoint]: the breakpoints dictionary.
        """
        return self._breakpoints

    @property
    def syscall_hooks(self: DebuggingContext) -> dict[int, SyscallHook]:
        """Get the syscall hooks dictionary.

        Returns:
            dict[int, SyscallHook]: the syscall hooks dictionary.
        """
        return self._syscall_hooks

    @property
    def signal_hooks(self: DebuggingContext) -> dict[int, SignalHook]:
        """Get the signal hooks dictionary.

        Returns:
            dict[int, SignalHook]: the signal hooks dictionary.
        """
        return self._signal_hooks

    def insert_new_breakpoint(self: DebuggingContext, bp: Breakpoint) -> None:
        """Insert a new breakpoint in the context.

        Args:
            bp (Breakpoint): the breakpoint to insert.
        """
        self._breakpoints[bp.address] = bp

    def remove_breakpoint(self: DebuggingContext, bp: Breakpoint) -> None:
        """Remove a breakpoint from the context.

        Args:
            bp (Breakpoint): the breakpoint to remove.
        """
        del self._breakpoints[bp.address]

    def insert_new_syscall_hook(self: DebuggingContext, syscall_hook: SyscallHook) -> None:
        """Insert a new syscall hook in the context.

        Args:
            syscall_hook (SyscallHook): the syscall hook to insert.
        """
        self._syscall_hooks[syscall_hook.syscall_number] = syscall_hook

    def remove_syscall_hook(self: DebuggingContext, syscall_hook: SyscallHook) -> None:
        """Remove a syscall hook from the context.

        Args:
            syscall_hook (SyscallHook): the syscall hook to remove.
        """
        del self._syscall_hooks[syscall_hook.syscall_number]

    def insert_new_signal_hook(self: DebuggingContext, signal_hook: SignalHook) -> None:
        """Insert a new signal hook in the context.

        Args:
            signal_hook (SignalHook): the signal hook to insert.
        """
        self._signal_hooks[signal_hook.signal_number] = signal_hook

    def remove_signal_hook(self: DebuggingContext, signal_hook: SignalHook) -> None:
        """Remove a signal hook from the context.

        Args:
            signal_hook (SignalHook): the signal hook to remove.
        """
        del self._signal_hooks[signal_hook.signal_number]

    @property
    def threads(self: DebuggingContext) -> dict[int, ThreadContext]:
        """Get the threads dictionary.

        Returns:
            dict[int, ThreadContext]: the threads dictionary.
        """
        return self._threads

    def insert_new_thread(self: DebuggingContext, thread: ThreadContext) -> None:
        """Insert a new thread in the context.

        Args:
            thread (ThreadContext): the thread to insert.
        """
        if thread in self._threads:
            raise RuntimeError("Thread already registered.")

        self._threads.append(thread)

    def set_thread_as_dead(self: DebuggingContext, thread_id: int) -> None:
        """Remove a thread from the context.

        Args:
            thread_id (int): the ID of the thread to remove.
        """
        for thread in self._threads:
            if thread.thread_id == thread_id:
                thread.dead = True
                break

    def get_thread_by_id(self: DebuggingContext, thread_id: int) -> ThreadContext:
        """Get a thread by its ID.

        Args:
            thread_id (int): the ID of the thread to get.

        Returns:
            ThreadContext: the thread with the specified ID.
        """
        for thread in self._threads:
            if thread.thread_id == thread_id and not thread.dead:
                return thread

        return None

    @property
    def running(self: DebuggingContext) -> bool:
        """Get the state of the process.

        Returns:
            bool: True if the process is running, False otherwise.
        """
        return self._is_running

    def set_running(self: DebuggingContext) -> None:
        """Set the state of the process to running."""
        self._is_running = True

    def set_stopped(self: DebuggingContext) -> None:
        """Set the state of the process to stopped."""
        self._is_running = False

    @property
    def dead(self: DebuggingContext) -> bool:
        """Get the state of the process.

        Returns:
            bool: True if the process is dead, False otherwise.
        """
        return not self._threads

    def resolve_address(self: DebuggingContext, address: int) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.

        Returns:
            int: The normalized and validated address.
        """
        maps = self.debugging_interface.maps()
        return normalize_and_validate_address(address, maps)

    def resolve_symbol(self: DebuggingContext, symbol: str) -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.

        Returns:
            int: The address of the symbol.
        """
        maps = self.debugging_interface.maps()
        address = resolve_symbol_in_maps(symbol, maps)
        return normalize_and_validate_address(address, maps)

    def interrupt(self: DebuggingContext) -> None:
        """Interrupt the debugged process."""
        self._resume_context.force_interrupt = True
        os.kill(self.process_id, signal.SIGSTOP)


__debugging_contexts: WeakKeyDictionary = WeakKeyDictionary()

__debugging_global_context = None
__debugging_context_lock = Lock()


def debugging_context() -> DebuggingContext:
    """Can be used to retrieve a temporarily-global debugging context."""
    if __debugging_global_context is None:
        raise RuntimeError("No debugging context available")
    return __debugging_global_context


def create_context(owner: object) -> DebuggingContext:
    """Create a debugging context.

    Args:
        owner (object): the owener of the debugging context.

    Returns:
        DebuggingContext: the debugging context.
    """
    __debugging_contexts[owner] = DebuggingContext()
    return __debugging_contexts[owner]


def provide_context(reference: object) -> DebuggingContext:
    """Provide a debugging context.

    Args:
        reference (object): the object that needs the debugging context.

    Returns:
        DebuggingContext: the debugging context.
    """
    if reference in __debugging_contexts:
        return __debugging_contexts[reference]

    if __debugging_global_context is None:
        raise RuntimeError("No debugging context available")

    __debugging_contexts[reference] = __debugging_global_context
    return __debugging_global_context


def link_context(reference: object, referrer: object = None) -> None:
    """Link a reference to a referrer.

    Args:
        reference (object): the object that needs the debugging context.
        referrer (object): the referrer object.
    """
    if referrer is not None:
        __debugging_contexts[reference] = __debugging_contexts[referrer]
    elif __debugging_global_context is not None:
        __debugging_contexts[reference] = __debugging_global_context
    else:
        raise RuntimeError("No debugging context available")


@contextmanager
def context_extend_from(referrer: object) -> ...:
    """Extend the debugging context.

    Args:
        referrer (object): the referrer object.

    Yields:
        DebuggingContext: the debugging context.
    """
    global __debugging_global_context

    with __debugging_context_lock:
        if referrer not in __debugging_contexts:
            raise RuntimeError("Referrer isn't linked to any context.")

        __debugging_global_context = __debugging_contexts[referrer]
        yield
        __debugging_global_context = None


def clear_context(reference: object) -> None:
    """Clear the debugging context.

    Args:
        reference (object): the object that needs the debugging context.
    """
    if reference in __debugging_contexts:
        context = __debugging_contexts[reference]
        # delete all keys whose value is context
        for key in list(__debugging_contexts):
            if __debugging_contexts[key] == context:
                del __debugging_contexts[key]
