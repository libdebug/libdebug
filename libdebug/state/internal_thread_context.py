#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.debugger.internal_debugger_instance_manager import (
    provide_internal_debugger,
)
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.debugging_utils import resolve_address_in_maps

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.register_holder import RegisterHolder
    from libdebug.data.registers import Registers
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.debugger.debugger import Debugger
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.memory.abstract_memory_view import AbstractMemoryView
    from libdebug.state.thread_context import ThreadContext


class InternalThreadContext:
    """This object represents internally a thread in the context of the target process. It holds information about the thread's state, registers and stack."""

    instruction_pointer: int
    """The thread's instruction pointer."""

    syscall_arg0: int
    """The thread's syscall argument 0."""

    syscall_arg1: int
    """The thread's syscall argument 1."""

    syscall_arg2: int
    """The thread's syscall argument 2."""

    syscall_arg3: int
    """The thread's syscall argument 3."""

    syscall_arg4: int
    """The thread's syscall argument 4."""

    syscall_arg5: int
    """The thread's syscall argument 5."""

    syscall_number: int
    """The thread's syscall number."""

    syscall_return: int
    """The thread's syscall return value."""

    regs: Registers
    """The thread's registers."""

    running: bool
    """A boolean indicating if the thread is running."""

    scheduled: bool
    """A boolean indicating if the thread should run."""

    dead: bool
    """A boolean indicating if the thread is dead."""

    exit_code: int | None
    """The thread's exit code."""

    exit_signal: int | None
    """The thread's exit signal."""

    signal_number: int
    """"The signal to forward to the thread."""

    public_thread_context: ThreadContext | None = None
    """The public thread context object."""

    _internal_debugger: InternalDebugger | None = None
    """The debugging context this thread belongs to."""

    _register_holder: RegisterHolder | None = None
    """The register holder object."""

    _thread_id: int
    """The thread's ID."""

    def __init__(self: InternalThreadContext, thread_id: int, registers: RegisterHolder) -> None:
        """Initializes the Thread Context."""
        self._internal_debugger = provide_internal_debugger(self)
        self._thread_id = thread_id
        self._register_holder = registers
        regs_class = self._register_holder.provide_regs_class()
        self.regs = regs_class(thread_id, self._register_holder.provide_regs())
        self._register_holder.apply_on_regs(self.regs, regs_class)
        self._register_holder.apply_on_thread(self, InternalThreadContext)
        self.running = False
        self.scheduled = False
        self.dead = False
        self.exit_code = None
        self.exit_signal = None
        self.signal_number = 0

    @property
    def debugger(self: InternalThreadContext) -> Debugger:
        """The debugging context this thread belongs to."""
        return self._internal_debugger.debugger

    @property
    def memory(self: InternalThreadContext) -> AbstractMemoryView:
        """The memory view of the debugged process."""
        return self._internal_debugger.memory

    @property
    def process_id(self: InternalThreadContext) -> int:
        """The process ID."""
        return self._internal_debugger.process_id

    @property
    def thread_id(self: InternalThreadContext) -> int:
        """The thread ID."""
        return self._thread_id

    @property
    def saved_ip(self: InternalThreadContext) -> int:
        """The return address of the current function."""
        self._internal_debugger.ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)

        try:
            return_address = stack_unwinder.get_return_address(self, self._internal_debugger.maps)
        except (OSError, ValueError) as e:
            raise ValueError(
                "Failed to get the return address. Check stack frame registers (e.g., base pointer).",
            ) from e

        return return_address

    def cont(self: InternalThreadContext) -> None:
        """Continues the execution of the thread."""
        self._internal_debugger.cont(self)

    def interrupt(self: InternalThreadContext) -> None:
        """Interrupts the execution of the thread."""
        self._internal_debugger.interrupt(self)

    def wait(self: InternalThreadContext) -> None:
        """Waits for the thread to stop."""
        self._internal_debugger.wait(self)

    def backtrace(self: InternalThreadContext, as_symbols: bool = False) -> list:
        """Returns the current backtrace of the thread.

        Args:
            as_symbols (bool, optional): Whether to return the backtrace as symbols
        """
        self._internal_debugger.ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)
        backtrace = stack_unwinder.unwind(self)
        if as_symbols:
            maps = self._internal_debugger.debugging_interface.get_maps()
            backtrace = [resolve_address_in_maps(x, maps) for x in backtrace]
        return backtrace

    def step(self: InternalThreadContext) -> None:
        """Executes a single instruction of the thread."""
        self._internal_debugger.step(self)

    def step_until(
        self: InternalThreadContext,
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
        self._internal_debugger.step_until(self, position, max_steps, file)

    def finish(self: InternalThreadContext, heuristic: str = "backtrace") -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(heuristic=heuristic, thread=self)

    def next(self: InternalThreadContext) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_debugger.next(self)

    def breakpoint(
        self: InternalThreadContext,
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
        return self._internal_debugger.breakpoint(position, hardware, condition, length, callback, file, self.thread_id)

    def watchpoint(
        self: InternalThreadContext,
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
        return self._internal_debugger.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
            file=file,
            thread_id=self.thread_id,
        )

    def handle_syscall(
        self: InternalThreadContext,
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
        return self._internal_debugger.handle_syscall(syscall, on_enter, on_exit, recursive, self.thread_id)

    def hijack_syscall(
        self: InternalThreadContext,
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
        return self._internal_debugger.hijack_syscall(
            original_syscall,
            new_syscall,
            recursive,
            self.thread_id,
            **kwargs,
        )

    def catch_signal(
        self: InternalThreadContext,
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
        return self._internal_debugger.catch_signal(signal, callback, recursive, self.thread_id)

    def hijack_signal(
        self: InternalThreadContext,
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
        return self._internal_debugger.hijack_signal(original_signal, new_signal, recursive, self.thread_id)

    def c(self: InternalThreadContext) -> None:
        """Alias for the `cont` method.

        Continues the execution of the thread.
        """
        self._internal_debugger.cont(self)

    def int(self: InternalThreadContext) -> None:
        """Alias for the `interrupt` method.

        Interrupts the execution of the thread.
        """
        self._internal_debugger.interrupt(self)

    def w(self: InternalThreadContext) -> None:
        """Alias for the `wait` method.

        Waits for the thread to stop.
        """
        self._internal_debugger.wait(self)

    def si(self: InternalThreadContext) -> None:
        """Alias for the `step` method.

        Executes a single instruction of the process.
        """
        self._internal_debugger.step(self)

    def su(
        self: InternalThreadContext,
        position: int | str,
        max_steps: int = -1,
    ) -> None:
        """Alias for the `step_until` method.

        Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
        """
        self._internal_debugger.step_until(self, position, max_steps)

    def fin(self: InternalThreadContext, heuristic: str = "backtrace") -> None:
        """Alias for the `finish` method. Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(self, heuristic)

    def ni(self: InternalThreadContext) -> None:
        """Alias for the `next` method. Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_debugger.next(self)

    def pprint_backtrace(self: InternalThreadContext) -> None:
        """Pretty prints the current backtrace of the thread."""
        self._internal_debugger.ensure_process_stopped()
        stack_unwinder = stack_unwinding_provider(self._internal_debugger.arch)
        backtrace = stack_unwinder.unwind(self)
        maps = self._internal_debugger.debugging_interface.get_maps()
        for return_address in backtrace:
            filtered_maps = maps.filter(return_address)
            return_address_symbol = resolve_address_in_maps(return_address, filtered_maps)
            permissions = filtered_maps[0].permissions
            if "rwx" in permissions:
                style = f"{ANSIColors.UNDERLINE}{ANSIColors.RED}"
            elif "x" in permissions:
                style = f"{ANSIColors.RED}"
            elif "w" in permissions:
                # This should not happen, but it's here for completeness
                style = f"{ANSIColors.YELLOW}"
            elif "r" in permissions:
                # This should not happen, but it's here for completeness
                style = f"{ANSIColors.GREEN}"
            if return_address_symbol[:2] == "0x":
                print(f"{style}{return_address:#x} {ANSIColors.RESET}")
            else:
                print(f"{style}{return_address:#x} <{return_address_symbol}> {ANSIColors.RESET}")

    def pprint_registers(self: InternalThreadContext) -> None:
        """Pretty prints the thread's registers."""
        for register in self._register_holder.provide_regs():
            self._pprint_reg(register)

    def pprint_regs(self: InternalThreadContext) -> None:
        """Alias for the `pprint_registers` method.

        Pretty prints the thread's registers.
        """
        self.pprint_registers()

    def pprint_registers_all(self: InternalThreadContext) -> None:
        """Pretty prints all the thread's registers."""
        self.pprint_registers()

        for t in self._register_holder.provide_special_regs():
            self._pprint_reg(t)

        for t in self._register_holder.provide_vector_fp_regs():
            print(f"{ANSIColors.BLUE}" + "{" + f"{ANSIColors.RESET}")
            for register in t:
                value = getattr(self.regs, register)
                formatted_value = f"{value:#x}" if isinstance(value, int) else str(value)
                print(f"  {ANSIColors.RED}{register}{ANSIColors.RESET}\t{formatted_value}")

            print(f"{ANSIColors.BLUE}" + "}" + f"{ANSIColors.RESET}")

    def pprint_regs_all(self: InternalThreadContext) -> None:
        """Alias for the `pprint_registers_all` method.

        Pretty prints all the thread's registers.
        """
        self.pprint_registers_all()

    def _pprint_reg(self: InternalThreadContext, register: str) -> None:
        attr = getattr(self.regs, register)
        color = ""
        style = ""
        formatted_attr = f"{attr:#x}"

        if maps := self._internal_debugger.maps.filter(attr):
            permissions = maps[0].permissions
            if "rwx" in permissions:
                color = ANSIColors.RED
                style = ANSIColors.UNDERLINE
            elif "x" in permissions:
                color = ANSIColors.RED
            elif "w" in permissions:
                color = ANSIColors.YELLOW
            elif "r" in permissions:
                color = ANSIColors.GREEN

        if color or style:
            formatted_attr = f"{color}{style}{attr:#x}{ANSIColors.RESET}"
        print(f"{ANSIColors.RED}{register}{ANSIColors.RESET}\t{formatted_attr}")
