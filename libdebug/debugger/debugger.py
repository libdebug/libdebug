#
# Copyright (c) 2023-2024  Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

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

    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.state.thread_context import ThreadContext


class Debugger:
    """The Debugger class is the main class of `libdebug`. It contains all the methods needed to run and interact with the process."""

    _sentinel: object = object()
    """A sentinel object."""

    _internal_debugger: InternalDebugger | None = None
    """The internal debugger object."""

    def __init__(self: Debugger) -> None:
        pass

    def post_init_(self: Debugger, internal_debugger: InternalDebugger) -> None:
        """Do not use this constructor directly. Use the `debugger` function instead."""
        self._internal_debugger = internal_debugger
        self._internal_debugger.start_up()

    def run(self: Debugger) -> None:
        """Starts the process and waits for it to stop."""
        return self._internal_debugger.run()

    def attach(self: Debugger, pid: int) -> None:
        """Attaches to an existing process."""
        self._internal_debugger.attach(pid)

    def detach(self: Debugger) -> None:
        """Detaches from the process."""
        self._internal_debugger.detach()

    def kill(self: Debugger) -> None:
        """Kills the process."""
        self._internal_debugger.kill()

    def terminate(self: Debugger) -> None:
        """Terminates the background thread.

        The debugger object cannot be used after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        self._internal_debugger.terminate()

    def cont(self: Debugger) -> None:
        """Continues the process."""
        self._internal_debugger.cont()

    def interrupt(self: Debugger) -> None:
        """Interrupts the process."""
        self._internal_debugger.interrupt()

    def wait(self: Debugger) -> None:
        """Waits for the process to stop."""
        self._internal_debugger.wait()

    def maps(self: Debugger) -> list[MemoryMap]:
        """Returns the memory maps of the process."""
        return self._internal_debugger.maps()

    def print_maps(self: Debugger) -> None:
        """Prints the memory maps of the process."""
        self._internal_debugger.print_maps()

    def breakpoint(
        self: Debugger,
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
        return self._internal_debugger.breakpoint(position, hardware, condition, length, callback, file)

    def watchpoint(
        self: Debugger,
        position: int | str,
        condition: str = "w",
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Sets a watchpoint at the specified location. Internally, watchpoints are implemented as breakpoints.

        Args:
            position (int | bytes): The location of the breakpoint.
            condition (str, optional): The trigger condition for the watchpoint (either "w", "rw" or "x").
            Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the
            watchpoint is hit. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid"
            (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t.
            the "binary" map file).
        """
        return self._internal_debugger.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
            file=file,
        )

    def catch_signal(
        self: Debugger,
        signal: int | str,
        callback: None | Callable[[ThreadContext, SignalCatcher], None] = None,
        recursive: bool = False,
    ) -> SignalCatcher:
        """Catch a signal in the target process.

        Args:
            signal (int | str): The signal to catch.
            callback (Callable[[ThreadContext, CaughtSignal], None], optional): A callback to be called when the signal
            is caught. Defaults to None.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher
            associated with the new signal should be considered as well. Defaults to False.

        Returns:
            CaughtSignal: The CaughtSignal object.
        """
        return self._internal_debugger.catch_signal(signal, callback, recursive)

    def hijack_signal(
        self: Debugger,
        original_signal: int | str,
        new_signal: int | str,
        recursive: bool = False,
    ) -> SyscallHandler:
        """Hijack a signal in the target process.

        Args:
            original_signal (int | str): The signal to hijack.
            new_signal (int | str): The signal to hijack the original signal with.
            recursive (bool, optional): Whether, when the signal is hijacked with another one, the signal catcher
            associated with the new signal should be considered as well. Defaults to False.

        Returns:
            CaughtSignal: The CaughtSignal object.
        """
        return self._internal_debugger.hijack_signal(original_signal, new_signal, recursive)

    def handle_syscall(
        self: Debugger,
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
        return self._internal_debugger.handle_syscall(syscall, on_enter, on_exit, recursive)

    def hijack_syscall(
        self: Debugger,
        original_syscall: int | str,
        new_syscall: int | str,
        recursive: bool = False,
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
        return self._internal_debugger.hijack_syscall(original_syscall, new_syscall, recursive, **kwargs)

    def gdb(self: Debugger, open_in_new_process: bool = True) -> None:
        """Migrates the current debugging session to GDB."""
        self._internal_debugger.gdb(open_in_new_process)

    def r(self: Debugger) -> None:
        """Alias for the `run` method.

        Starts the process and waits for it to stop.
        """
        self._internal_debugger.run()

    def c(self: Debugger) -> None:
        """Alias for the `cont` method.

        Continues the process.
        """
        self._internal_debugger.cont()

    def int(self: Debugger) -> None:
        """Alias for the `interrupt` method.

        Interrupts the process.
        """
        self._internal_debugger.interrupt()

    def w(self: Debugger) -> None:
        """Alias for the `wait` method.

        Waits for the process to stop.
        """
        self._internal_debugger.wait()

    def bp(
        self: Debugger,
        position: int | str,
        hardware: bool = False,
        condition: str | None = None,
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
        file: str = "hybrid",
    ) -> Breakpoint:
        """Alias for the `breakpoint` method.

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
        return self._internal_debugger.breakpoint(position, hardware, condition, length, callback, file)

    def wp(
        self: Debugger,
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
            condition (str, optional): The trigger condition for the watchpoint (either "w", "rw" or "x").
            Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the
            watchpoint is hit. Defaults to None.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid"
            (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t.
            the "binary" map file).
        """
        return self._internal_debugger.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
            file=file,
        )

    @property
    def threads(self: Debugger) -> list[ThreadContext]:
        """Get the list of threads in the process."""
        return self._internal_debugger.threads

    @property
    def breakpoints(self: Debugger) -> dict[int, Breakpoint]:
        """Get the breakpoints set on the process."""
        return self._internal_debugger.breakpoints

    @property
    def handled_syscalls(self: InternalDebugger) -> dict[int, SyscallHandler]:
        """Get the handled syscalls dictionary.

        Returns:
            dict[int, HandledSyscall]: the handled syscalls dictionary.
        """
        return self._internal_debugger.handled_syscalls

    @property
    def caught_signals(self: InternalDebugger) -> dict[int, SignalCatcher]:
        """Get the caught signals dictionary.

        Returns:
            dict[int, CaughtSignal]: the caught signals dictionary.
        """
        return self._internal_debugger.caught_signals

    @property
    def pprint_syscalls(self: Debugger) -> bool:
        """Get the state of the pprint_syscalls flag.

        Returns:
            bool: True if the debugger should pretty print syscalls, False otherwise.
        """
        return self._internal_debugger.pprint_syscalls

    @pprint_syscalls.setter
    def pprint_syscalls(self: Debugger, value: bool) -> None:
        """Set the state of the pprint_syscalls flag.

        Args:
            value (bool): the value to set.
        """
        if not isinstance(value, bool):
            raise TypeError("pprint_syscalls must be a boolean")
        if value:
            self._internal_debugger.enable_pretty_print()
        else:
            self._internal_debugger.disable_pretty_print()

        self._internal_debugger.pprint_syscalls = value

    @contextmanager
    def pprint_syscalls_context(self: Debugger, value: bool) -> ...:
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
    def syscalls_to_pprint(self: Debugger) -> list[str] | None:
        """Get the syscalls to pretty print.

        Returns:
            list[str]: The syscalls to pretty print.
        """
        if self._internal_debugger.syscalls_to_pprint is None:
            return None
        else:
            return [resolve_syscall_name(v) for v in self._internal_debugger.syscalls_to_pprint]

    @syscalls_to_pprint.setter
    def syscalls_to_pprint(self: Debugger, value: list[int | str] | None) -> None:
        """Get the syscalls to pretty print.

        Args:
            value (list[int | str] | None): The syscalls to pretty print.
        """
        if value is None:
            self._internal_debugger.syscalls_to_pprint = None
        elif isinstance(value, list):
            self._internal_debugger.syscalls_to_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_pprint must be a list of integers or strings or None.",
            )
        if self._internal_debugger.pprint_syscalls:
            self._internal_debugger.enable_pretty_print()

    @property
    def syscalls_to_not_pprint(self: Debugger) -> list[str] | None:
        """Get the syscalls to not pretty print.

        Returns:
            list[str]: The syscalls to not pretty print.
        """
        if self._internal_debugger.syscalls_to_not_pprint is None:
            return None
        else:
            return [resolve_syscall_name(v) for v in self._internal_debugger.syscalls_to_not_pprint]

    @syscalls_to_not_pprint.setter
    def syscalls_to_not_pprint(self: Debugger, value: list[int | str] | None) -> None:
        """Get the syscalls to not pretty print.

        Args:
            value (list[int | str] | None): The syscalls to not pretty print.
        """
        if value is None:
            self._internal_debugger.syscalls_to_not_pprint = None
        elif isinstance(value, list):
            self._internal_debugger.syscalls_to_not_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_not_pprint must be a list of integers or strings or None.",
            )
        if self._internal_debugger.pprint_syscalls:
            self._internal_debugger.enable_pretty_print()

    @property
    def signals_to_block(self: Debugger) -> list[str]:
        """Get the signals to not forward to the process.

        Returns:
            list[str]: The signals to block.
        """
        return [resolve_signal_name(v) for v in self._internal_debugger.signals_to_block]

    @signals_to_block.setter
    def signals_to_block(self: Debugger, signals: list[int | str]) -> None:
        """Set the signal to not forward to the process.

        Args:
            signals (list[int | str]): The signals to block.
        """
        if not isinstance(signals, list):
            raise TypeError("signals_to_block must be a list of integers or strings")

        signals = [v if isinstance(v, int) else resolve_signal_number(v) for v in signals]

        if not set(signals).issubset(get_all_signal_numbers()):
            raise ValueError("Invalid signal number.")

        self._internal_debugger.signals_to_block = signals

    def __getattr__(self: Debugger, name: str) -> object:
        """This function is called when an attribute is not found in the `Debugger` object.

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

    def __setattr__(self: Debugger, name: str, value: object) -> None:
        """This function is called when an attribute is set in the `Debugger` object.

        It is used to forward the call to the first `ThreadContext` object.
        """
        # First we check if the attribute is available in the `Debugger` object
        if hasattr(Debugger, name):
            super().__setattr__(name, value)
        else:
            thread_context = self.threads[0]
            setattr(thread_context, name, value)
