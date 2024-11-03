#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.utils.signal_utils import resolve_signal_name, resolve_signal_number

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.registers import Registers
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.debugger.debugger import Debugger
    from libdebug.memory.abstract_memory_view import AbstractMemoryView
    from libdebug.state.internal_thread_context import InternalThreadContext


class ThreadContext:
    """This object represents a thread in the context of the target process. It holds information about the thread's state, registers and stack."""

    _internal_thread_context: InternalThreadContext | None = None
    """The debugging context this thread belongs to."""

    def __init__(self: ThreadContext, internal_thread_context: InternalThreadContext) -> None:
        """Initializes the Thread Context."""
        self._internal_thread_context = internal_thread_context

    @property
    def debugger(self: ThreadContext) -> Debugger:
        """The debugging context this thread belongs to."""
        return self._internal_thread_context.debugger

    @property
    def regs(self: ThreadContext) -> Registers:
        """The thread's registers."""
        return self._internal_thread_context.regs

    @property
    def instruction_pointer(self: ThreadContext) -> int:
        """The thread's instruction pointer."""
        return self._internal_thread_context.instruction_pointer

    @instruction_pointer.setter
    def instruction_pointer(self: ThreadContext, value: int) -> None:
        """Set the thread's instruction pointer."""
        self._internal_thread_context.instruction_pointer = value

    @property
    def syscall_arg0(self: ThreadContext) -> int:
        """The thread's syscall argument 0."""
        return self._internal_thread_context.syscall_arg0

    @syscall_arg0.setter
    def syscall_arg0(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 0."""
        self._internal_thread_context.syscall_arg0 = value

    @property
    def syscall_arg1(self: ThreadContext) -> int:
        """The thread's syscall argument 1."""
        return self._internal_thread_context.syscall_arg1

    @syscall_arg1.setter
    def syscall_arg1(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 1."""
        self._internal_thread_context.syscall_arg1 = value

    @property
    def syscall_arg2(self: ThreadContext) -> int:
        """The thread's syscall argument 2."""
        return self._internal_thread_context.syscall_arg2

    @syscall_arg2.setter
    def syscall_arg2(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 2."""
        self._internal_thread_context.syscall_arg2 = value

    @property
    def syscall_arg3(self: ThreadContext) -> int:
        """The thread's syscall argument 3."""
        return self._internal_thread_context.syscall_arg3

    @syscall_arg3.setter
    def syscall_arg3(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 3."""
        self._internal_thread_context.syscall_arg3 = value

    @property
    def syscall_arg4(self: ThreadContext) -> int:
        """The thread's syscall argument 4."""
        return self._internal_thread_context.syscall_arg4

    @syscall_arg4.setter
    def syscall_arg4(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 4."""
        self._internal_thread_context.syscall_arg4 = value

    @property
    def syscall_arg5(self: ThreadContext) -> int:
        """The thread's syscall argument 5."""
        return self._internal_thread_context.syscall_arg5

    @syscall_arg5.setter
    def syscall_arg5(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall argument 5."""
        self._internal_thread_context.syscall_arg5 = value

    @property
    def syscall_number(self: ThreadContext) -> int:
        """The thread's syscall number."""
        return self._internal_thread_context.syscall_number

    @syscall_number.setter
    def syscall_number(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall number."""
        self._internal_thread_context.syscall_number = value

    @property
    def syscall_return(self: ThreadContext) -> int:
        """The thread's syscall return value."""
        return self._internal_thread_context.syscall_return

    @syscall_return.setter
    def syscall_return(self: ThreadContext, value: int) -> None:
        """Set the thread's syscall return value."""
        self._internal_thread_context.syscall_return = value

    @property
    def memory(self: ThreadContext) -> AbstractMemoryView:
        """The memory view of the debugged process."""
        return self._internal_thread_context.memory

    @property
    def mem(self: ThreadContext) -> AbstractMemoryView:
        """Alias for the `memory` property.

        Get the memory view of the process.
        """
        return self._internal_thread_context.memory

    @property
    def process_id(self: ThreadContext) -> int:
        """The process ID."""
        return self._internal_thread_context.process_id

    @property
    def pid(self: ThreadContext) -> int:
        """Alias for `process_id` property.

        The process ID.
        """
        return self._internal_thread_context.process_id

    @property
    def thread_id(self: ThreadContext) -> int:
        """The thread ID."""
        return self._internal_thread_context.thread_id

    @property
    def tid(self: ThreadContext) -> int:
        """The thread ID."""
        return self._internal_thread_context.thread_id

    @property
    def saved_ip(self: ThreadContext) -> int:
        """The return address of the current function."""
        return self._internal_thread_context.saved_ip

    @property
    def running(self: ThreadContext) -> bool:
        """Get the state of the thread.

        Returns:
            bool: True if the thread is running, False otherwise.
        """
        return self._internal_thread_context.running

    @property
    def scheduled(self: ThreadContext) -> bool:
        """If the thread is scheduled to run."""
        return self._internal_thread_context.scheduled

    @property
    def dead(self: ThreadContext) -> bool:
        """Whether the thread is dead."""
        return self._internal_thread_context.dead

    @property
    def exit_code(self: ThreadContext) -> int | None:
        """The thread's exit code."""
        # TODO: ensure thread stopped
        self._internal_thread_context._internal_debugger.ensure_process_stopped()
        if not self._internal_thread_context.dead:
            liblog.warning("Thread is not dead. No exit code available.")
        elif (exit_code := self._internal_thread_context.exit_code) is None and (
            exit_signal := self._internal_thread_context.exit_signal
        ) is not None:
            liblog.warning(
                "Thread exited with signal %s. No exit code available.",
                resolve_signal_name(exit_signal),
            )
        return exit_code

    @property
    def exit_signal(self: ThreadContext) -> str | None:
        """The thread's exit signal."""
        # TODO: ensure thread stopped
        self._internal_thread_context._internal_debugger.ensure_process_stopped()
        if not self._internal_thread_context.dead:
            liblog.warning("Thread is not dead. No exit signal available.")
            return None
        elif (exit_signal := self._internal_thread_context.exit_signal) is None and (
            exit_code := self._internal_thread_context.exit_code
        ) is not None:
            liblog.warning("Thread exited with code %d. No exit signal available.", exit_code)
            return None
        return resolve_signal_name(exit_signal)

    @property
    def signal(self: ThreadContext) -> str | None:
        """The signal will be forwarded to the thread."""
        # TODO: ensure thread stopped
        self._internal_thread_context._internal_debugger.ensure_process_stopped()
        return (
            None
            if self._internal_thread_context.signal_number == 0
            else resolve_signal_name(self._internal_thread_context.signal_number)
        )

    @signal.setter
    def signal(self: ThreadContext, signal: str | int) -> None:
        """Set the signal to forward to the thread."""
        # TODO: ensure thread stopped
        self._internal_thread_context._internal_debugger.ensure_process_stopped()
        if (signal_number := self._internal_thread_context.signal_number) != 0:
            liblog.debugger(
                f"Overwriting signal {resolve_signal_name(signal_number)} with {resolve_signal_name(signal) if isinstance(signal, int) else signal}.",
            )
        if isinstance(signal, str):
            signal = resolve_signal_number(signal)
        self._internal_thread_context.signal_number = signal
        self._internal_thread_context._internal_debugger.resume_context.threads_with_signals_to_forward.append(
            self.thread_id
        )

    @property
    def signal_number(self: ThreadContext) -> int:
        """The signal number to forward to the thread."""
        self._internal_thread_context._internal_debugger.ensure_process_stopped()
        return self._internal_thread_context.signal_number

    def cont(self: ThreadContext) -> None:
        """Continues the execution of the thread."""
        self._internal_thread_context.cont()

    def interrupt(self: ThreadContext) -> None:
        """Interrupts the execution of the thread."""
        self._internal_thread_context.interrupt()

    def wait(self: ThreadContext) -> None:
        """Waits for the thread to stop."""
        self._internal_thread_context.wait()

    def backtrace(self: ThreadContext, as_symbols: bool = False) -> list:
        """Returns the current backtrace of the thread.

        Args:
            as_symbols (bool, optional): Whether to return the backtrace as symbols
        """
        return self._internal_thread_context.backtrace(as_symbols)

    def step(self: ThreadContext) -> None:
        """Executes a single instruction of the specified thread."""
        self._internal_thread_context.step()

    def step_until(
        self: ThreadContext,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
    ) -> None:
        """Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        self._internal_thread_context.step_until(position, max_steps, file)

    def finish(self: ThreadContext, heuristic: str = "backtrace") -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_thread_context.finish(heuristic)

    def next(self: ThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_thread_context.next()

    def breakpoint(
        self: ThreadContext,
        position: int | str,
        hardware: bool = False,
        condition: str = "x",
        length: int = 1,
        callback: None | bool | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Sets a breakpoint at the specified location, per-thread scoped.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (None | bool | Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. If True, an empty callback will be set. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        return self._internal_thread_context.breakpoint(position, hardware, condition, length, callback, file)

    def watchpoint(
        self: ThreadContext,
        position: int | str,
        condition: str = "w",
        length: int = 1,
        callback: None | bool | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Sets a watchpoint at the specified location, per-thread scoped. Internally, watchpoints are implemented as breakpoints.

        Args:
            position (int | bytes): The location of the breakpoint.
            condition (str, optional): The trigger condition for the watchpoint (either "w", "rw" or "x"). Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (None | bool | Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the watchpoint is hit. If True, an empty callback will be set. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        return self._internal_thread_context.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
            file=file,
        )

    def bp(
        self: ThreadContext,
        position: int | str,
        hardware: bool = False,
        condition: str = "x",
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Alias for the `breakpoint` method.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        return self._internal_thread_context.breakpoint(position, hardware, condition, length, callback, file)

    def wp(
        self: ThreadContext,
        position: int | str,
        condition: str = "w",
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Alias for the `watchpoint` method.

        Sets a watchpoint at the specified location. Internally, watchpoints are implemented as breakpoints.

        Args:
            position (int | bytes): The location of the breakpoint.
            condition (str, optional): The trigger condition for the watchpoint (either "w", "rw" or "x"). Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the watchpoint is hit. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        return self._internal_thread_context.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
            file=file,
        )

    def handle_syscall(
        self: ThreadContext,
        syscall: int | str,
        on_enter: None | bool | Callable[[ThreadContext, SyscallHandler], None] = None,
        on_exit: None | bool | Callable[[ThreadContext, SyscallHandler], None] = None,
        recursive: bool = False,
    ) -> SyscallHandler:
        """Handle a syscall in the target thread.

        Args:
            syscall (int | str): The syscall name or number to handle. If "*", "ALL", "all" or -1 is passed, all syscalls will be handled.
            on_enter (None | bool |Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is entered. If True, an empty callback will be set. Defaults to None.
            on_exit (None | bool | Callable[[ThreadContext, SyscallHandler], None], optional): The callback to execute when the syscall is exited. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.

        Returns:
            SyscallHandler: The SyscallHandler object.
        """
        return self._internal_thread_context.handle_syscall(syscall, on_enter, on_exit, recursive)

    def hijack_syscall(
        self: ThreadContext,
        original_syscall: int | str,
        new_syscall: int | str,
        recursive: bool = False,
        **kwargs: int,
    ) -> SyscallHandler:
        """Hijacks a syscall in the target thread.

        Args:
            original_syscall (int | str): The syscall name or number to hijack. If "*", "ALL", "all" or -1 is passed, all syscalls will be hijacked.
            new_syscall (int | str): The syscall name or number to hijack the original syscall with.
            recursive (bool, optional): Whether, when the syscall is hijacked with another one, the syscall handler associated with the new syscall should be considered as well. Defaults to False.
            **kwargs: (int, optional): The arguments to pass to the new syscall.

        Returns:
            SyscallHandler: The SyscallHandler object.
        """
        return self._internal_thread_context.hijack_syscall(original_syscall, new_syscall, recursive, **kwargs)

    def catch_signal(
        self: ThreadContext,
        signal: int | str,
        callback: None | bool | Callable[[ThreadContext, SignalCatcher], None] = None,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Catch a signal in the target thread.

        Args:
            signal (int | str): The signal to catch. If "*", "ALL", "all" or -1 is passed, all signals will be caught.
            callback (None | bool | Callable[[ThreadContext, SignalCatcher], None], optional): A callback to be called when the signal is caught. If True, an empty callback will be set. Defaults to None.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.

        Returns:
            SignalCatcher: The SignalCatcher object.
        """
        return self._internal_thread_context.catch_signal(signal, callback, recursive)

    def hijack_signal(
        self: ThreadContext,
        original_signal: int | str,
        new_signal: int | str,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Hijack a signal in the target thread.

        Args:
            original_signal (int | str): The signal to hijack. If "*", "ALL", "all" or -1 is passed, all signals will be hijacked.
            new_signal (int | str): The signal to hijack the original signal with.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher associated with the new signal should be considered as well. Defaults to False.

        Returns:
            SignalCatcher: The SignalCatcher object.
        """
        return self._internal_thread_context.hijack_signal(original_signal, new_signal, recursive)

    def c(self: ThreadContext) -> None:
        """Alias for the `cont` method.

        Continues the execution of the thread.
        """
        self._internal_thread_context.cont()

    def int(self: ThreadContext) -> None:
        """Alias for the `interrupt` method.

        Interrupts the execution of the thread.
        """
        self._internal_thread_context.interrupt()

    def w(self: ThreadContext) -> None:
        """Alias for the `wait` method.

        Waits for the thread to stop.
        """
        self._internal_thread_context.wait()

    def si(self: ThreadContext) -> None:
        """Alias for the `step` method.

        Executes a single instruction of the process.
        """
        self._internal_thread_context.step()

    def su(
        self: ThreadContext,
        position: int | str,
        max_steps: int = -1,
    ) -> None:
        """Alias for the `step_until` method.

        Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        self._internal_thread_context.step_until(position, max_steps)

    def fin(self: ThreadContext, heuristic: str = "backtrace") -> None:
        """Alias for the `finish` method. Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_thread_context.finish(heuristic)

    def ni(self: ThreadContext) -> None:
        """Alias for the `next` method. Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_thread_context.next()

    def pprint_backtrace(self: ThreadContext) -> None:
        """Pretty prints the current backtrace of the thread."""
        self._internal_thread_context.pprint_backtrace()

    def pprint_registers(self: ThreadContext) -> None:
        """Pretty prints the thread's registers."""
        self._internal_thread_context.pprint_registers()

    def pprint_regs(self: ThreadContext) -> None:
        """Alias for the `pprint_registers` method.

        Pretty prints the thread's registers.
        """
        self._internal_thread_context.pprint_registers()

    def pprint_registers_all(self: ThreadContext) -> None:
        """Pretty prints all the thread's registers."""
        self._internal_thread_context.pprint_registers_all()

    def pprint_regs_all(self: ThreadContext) -> None:
        """Alias for the `pprint_registers_all` method.

        Pretty prints all the thread's registers.
        """
        self._internal_thread_context.pprint_registers_all()

    def __repr__(self: ThreadContext) -> str:
        """Returns a string representation of the object."""
        repr_str = "ThreadContext()\n"
        repr_str += f"  Thread ID: {self.thread_id}\n"
        repr_str += f"  Process ID: {self.process_id}\n"
        repr_str += f"  Instruction Pointer: {self.instruction_pointer:#x}\n"
        repr_str += f"  Dead: {self.dead}\n"
        return repr_str
