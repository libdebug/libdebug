#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.utils.oop.alias import check_alias

if TYPE_CHECKING:
    from libdebug.commlink.pipe_manager import PipeManager


class ExecutionMixin:
    """Process lifecycle controls and single-stepping helpers."""

    @check_alias("r")
    def run(self: ExecutionMixin, timeout: float = -1, redirect_pipes: bool = True) -> PipeManager | None:
        """Starts the process and waits for it to stop.

        Args:
            timeout (float): The timeout for the process to run. If -1, the process will run indefinitely.
            redirect_pipes (bool): Whether to hook and redirect the pipes of the process to a PipeManager.
        """
        return self._internal_debugger.run(timeout, redirect_pipes)

    def attach(self: ExecutionMixin, pid: int) -> None:
        """Attaches to an existing process."""
        self._internal_debugger.attach(pid)

    def detach(self: ExecutionMixin) -> None:
        """Detaches from the process."""
        self._internal_debugger.detach()

    def kill(self: ExecutionMixin) -> None:
        """Kills the process."""
        self._internal_debugger.kill()

    def terminate(self: ExecutionMixin) -> None:
        """Interrupts the process, kills it and then terminates the background thread.

        The debugger object will not be usable after this method is called.
        This method should only be called to free up resources when the debugger object is no longer needed.
        """
        self._internal_debugger.terminate()

    @check_alias("c")
    def cont(self: ExecutionMixin) -> None:
        """Continues the process."""
        self._internal_debugger.cont()

    @check_alias("int")
    def interrupt(self: ExecutionMixin) -> None:
        """Interrupts the process."""
        self._internal_debugger.interrupt()

    @check_alias("w")
    def wait(self: ExecutionMixin) -> None:
        """Waits for the process to stop."""
        self._internal_debugger.wait()

    def r(self: ExecutionMixin, timeout: float = -1, redirect_pipes: bool = True) -> PipeManager | None:
        """Alias for the `run` method.

        Starts the process and waits for it to stop.

        Args:
            timeout (float): The timeout for the process to run. If -1, the process will run indefinitely.
            redirect_pipes (bool): Whether to hook and redirect the pipes of the process to a PipeManager.
        """
        return self._internal_debugger.run(timeout, redirect_pipes)

    def c(self: ExecutionMixin) -> None:
        """Alias for the `cont` method.

        Continues the process.
        """
        self._internal_debugger.cont()

    def int(self: ExecutionMixin) -> None:
        """Alias for the `interrupt` method.

        Interrupts the process.
        """
        self._internal_debugger.interrupt()

    def w(self: ExecutionMixin) -> None:
        """Alias for the `wait` method.

        Waits for the process to stop.
        """
        self._internal_debugger.wait()

    @check_alias("si")
    def step(self: ExecutionMixin) -> None:
        """Executes a single instruction of the process."""
        self._internal_debugger.step(self)

    @check_alias("su")
    def step_until(
        self: ExecutionMixin,
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

    @check_alias("fin")
    def finish(self: ExecutionMixin, heuristic: str = "backtrace") -> None:
        """Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(self, heuristic=heuristic)

    @check_alias("ni")
    def next(self: ExecutionMixin) -> None:
        """Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns."""
        self._internal_debugger.next(self)

    def si(self: ExecutionMixin) -> None:
        """Alias for the `step` method.

        Executes a single instruction of the process.
        """
        self._internal_debugger.step(self)

    def su(
        self: ExecutionMixin,
        position: int | str,
        max_steps: int = -1,
        file: str = "hybrid",
    ) -> None:
        """Alias for the `step_until` method.

        Executes instructions of the process until the specified location is reached.

        Args:
            position (int | bytes): The location to reach.
            max_steps (int, optional): The maximum number of steps to execute. Defaults to -1.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        self._internal_debugger.step_until(self, position, max_steps, file)

    def fin(self: ExecutionMixin, heuristic: str = "backtrace") -> None:
        """Alias for the `finish` method.

        Continues execution until the current function returns or the process stops.

        The command requires a heuristic to determine the end of the function. The available heuristics are:
        - `backtrace`: The debugger will place a breakpoint on the saved return address found on the stack and continue execution on all threads.
        - `step-mode`: The debugger will step on the specified thread until the current function returns. This will be slower.

        Args:
            heuristic (str, optional): The heuristic to use. Defaults to "backtrace".
        """
        self._internal_debugger.finish(self, heuristic)

    def ni(self: ExecutionMixin) -> None:
        """Alias for the `next` method.

        Executes the next instruction of the process. If the instruction is a call, the debugger will continue until the called function returns.
        """
        self._internal_debugger.next(self)
