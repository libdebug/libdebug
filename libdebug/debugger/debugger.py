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
    from libdebug.data.memory_view import MemoryView
    from libdebug.data.signal_hook import SignalHook
    from libdebug.data.syscall_hook import SyscallHook
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

    def breakpoint(
        self: Debugger,
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
        return self._internal_debugger.breakpoint(position, hardware, condition, length, callback)

    def watchpoint(
        self: Debugger,
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
        return self._internal_debugger.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
        )

    def hook_signal(
        self: Debugger,
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
        return self._internal_debugger.hook_signal(signal_to_hook, callback, hook_hijack)

    def unhook_signal(self: Debugger, hook: SignalHook) -> None:
        """Unhooks a signal in the target process.

        Args:
            hook (SignalHook): The signal hook to unhook.
        """
        self._internal_debugger.unhook_signal(hook)

    def hijack_signal(
        self: Debugger,
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
        return self._internal_debugger.hijack_signal(original_signal, new_signal, hook_hijack)

    def hook_syscall(
        self: Debugger,
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
        return self._internal_debugger.hook_syscall(syscall, on_enter, on_exit, hook_hijack)

    def unhook_syscall(self: Debugger, hook: SyscallHook) -> None:
        """Unhooks a syscall in the target process.

        Args:
            hook (SyscallHook): The syscall hook to unhook.
        """
        self._internal_debugger.unhook_syscall(hook)

    def hijack_syscall(
        self: Debugger,
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
        return self._internal_debugger.hijack_syscall(original_syscall, new_syscall, hook_hijack, **kwargs)

    def migrate_to_gdb(self: Debugger, open_in_new_process: bool = True) -> None:
        """Migrates the current debugging session to GDB."""
        self._internal_debugger.migrate_to_gdb(open_in_new_process)

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
    ) -> Breakpoint:
        """Alias for the `breakpoint` method.

        Sets a breakpoint at the specified location.

        Args:
            position (int | bytes): The location of the breakpoint.
            hardware (bool, optional): Whether the breakpoint should be hardware-assisted or purely software. Defaults to False.
            condition (str, optional): The trigger condition for the breakpoint. Defaults to None.
            length (int, optional): The length of the breakpoint. Only for watchpoints. Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the breakpoint is hit. Defaults to None.
        """
        return self._internal_debugger.breakpoint(position, hardware, condition, length, callback)

    def wp(
        self: Debugger,
        position: int | str,
        condition: str = "w",
        length: int = 1,
        callback: None | Callable[[ThreadContext, Breakpoint], None] = None,
    ) -> Breakpoint:
        """Alias for the `watchpoint` method.

        Sets a watchpoint at the specified location. Internally, watchpoints are implemented as breakpoints.

        Args:
            position (int | bytes): The location of the breakpoint.
            condition (str, optional): The trigger condition for the watchpoint (either "r", "rw" or "x"). Defaults to "w".
            length (int, optional): The size of the word in being watched (1, 2, 4 or 8). Defaults to 1.
            callback (Callable[[ThreadContext, Breakpoint], None], optional): A callback to be called when the watchpoint is hit. Defaults to None.
        """
        return self._internal_debugger.breakpoint(
            position,
            hardware=True,
            condition=condition,
            length=length,
            callback=callback,
        )

    @property
    def threads(self: Debugger) -> list[ThreadContext]:
        """Get the list of threads in the process."""
        return self._internal_debugger.threads

    @property
    def memory(self: Debugger) -> MemoryView:
        """Get the memory view of the process."""
        return self._internal_debugger.memory

    @property
    def mem(self: Debugger) -> MemoryView:
        """Alias for the `memory` property.

        Get the memory view of the process.
        """
        return self._internal_debugger.memory

    @property
    def breakpoints(self: Debugger) -> dict[int, Breakpoint]:
        """Get the breakpoints set on the process."""
        return self._internal_debugger.breakpoints

    @property
    def syscall_hooks(self: InternalDebugger) -> dict[int, SyscallHook]:
        """Get the syscall hooks dictionary.

        Returns:
            dict[int, SyscallHook]: the syscall hooks dictionary.
        """
        return self._internal_debugger.syscall_hooks

    @property
    def signal_hooks(self: InternalDebugger) -> dict[int, SignalHook]:
        """Get the signal hooks dictionary.

        Returns:
            dict[int, SignalHook]: the signal hooks dictionary.
        """
        return self._internal_debugger.signal_hooks

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