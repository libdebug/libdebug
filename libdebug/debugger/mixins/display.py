#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from contextlib import contextmanager

from libdebug.liblog import liblog
from libdebug.utils.oop.alias import check_alias
from libdebug.utils.syscall_utils import (
    resolve_syscall_name,
    resolve_syscall_number,
)


class DisplayMixin:
    """Utilities that pretty print debugger data and shape representation."""

    # Pretty-print helpers
    def print_maps(self: DisplayMixin) -> None:
        """Prints the memory maps of the process."""
        liblog.warning("The `print_maps` method is deprecated. Use `d.pprint_maps` instead.")
        self._internal_debugger.pprint_maps()

    def pprint_maps(self: DisplayMixin) -> None:
        """Prints the memory maps of the process."""
        self._internal_debugger.pprint_maps()

    def pprint_backtrace(self: DisplayMixin) -> None:
        """Pretty pints the current backtrace of the main thread."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].pprint_backtrace()

    @check_alias("pprint_regs")
    def pprint_registers(self: DisplayMixin) -> None:
        """Pretty prints the main thread's registers."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].pprint_registers()

    def pprint_regs(self: DisplayMixin) -> None:
        """Alias for the `pprint_registers` method.

        Pretty prints the main thread's registers.
        """
        self.pprint_registers()

    @check_alias("pprint_regs_all")
    def pprint_registers_all(self: DisplayMixin) -> None:
        """Pretty prints all the main thread's registers."""
        if not self.threads:
            raise RuntimeError("No threads available. Did you call `run` or `attach`?")
        self.threads[0].pprint_registers_all()

    def pprint_regs_all(self: DisplayMixin) -> None:
        """Alias for the `pprint_registers_all` method.

        Pretty prints all the main thread's registers.
        """
        self.pprint_registers_all()

    def pprint_memory(
        self: DisplayMixin,
        start: int,
        end: int,
        file: str = "hybrid",
        override_word_size: int | None = None,
        integer_mode: bool = False,
    ) -> None:
        """Pretty prints the memory contents of the process.

        Args:
            start (int): The start address of the memory region.
            end (int): The end address of the memory region.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
            override_word_size (int, optional): The word size to use for the memory dump. Defaults to None.
            integer_mode (bool, optional): Whether to print the memory contents as integers. Defaults to False.
        """
        self._internal_debugger.pprint_memory(start, end, file, override_word_size, integer_mode)

    # Syscall pretty-print configuration
    @property
    def pprint_syscalls(self: DisplayMixin) -> bool:
        """Get the state of the pprint_syscalls flag.

        Returns:
            bool: True if the debugger should pretty print syscalls, False otherwise.
        """
        return self._internal_debugger.pprint_syscalls

    @pprint_syscalls.setter
    def pprint_syscalls(self: DisplayMixin, value: bool) -> None:
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
    def pprint_syscalls_context(self: DisplayMixin, value: bool) -> ...:
        """A context manager to temporarily change the state of the pprint_syscalls flag.

        Args:
            value (bool): the value to set.
        """
        old_value = self.pprint_syscalls
        self.pprint_syscalls = value
        yield
        self.pprint_syscalls = old_value

    @property
    def syscalls_to_pprint(self: DisplayMixin) -> list[str] | None:
        """Get the syscalls to pretty print.

        Returns:
            list[str]: The syscalls to pretty print.
        """
        if self._internal_debugger.syscalls_to_pprint is None:
            return None
        else:
            return [
                resolve_syscall_name(self._internal_debugger.arch, v)
                for v in self._internal_debugger.syscalls_to_pprint
            ]

    @syscalls_to_pprint.setter
    def syscalls_to_pprint(self: DisplayMixin, value: list[int | str] | None) -> None:
        """Get the syscalls to pretty print.

        Args:
            value (list[int | str] | None): The syscalls to pretty print.
        """
        if value is None:
            self._internal_debugger.syscalls_to_pprint = None
        elif isinstance(value, list):
            self._internal_debugger.syscalls_to_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(self._internal_debugger.arch, v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_pprint must be a list of integers or strings or None.",
            )
        if self._internal_debugger.pprint_syscalls:
            self._internal_debugger.enable_pretty_print()

    @property
    def syscalls_to_not_pprint(self: DisplayMixin) -> list[str] | None:
        """Get the syscalls to not pretty print.

        Returns:
            list[str]: The syscalls to not pretty print.
        """
        if self._internal_debugger.syscalls_to_not_pprint is None:
            return None
        else:
            return [
                resolve_syscall_name(self._internal_debugger.arch, v)
                for v in self._internal_debugger.syscalls_to_not_pprint
            ]

    @syscalls_to_not_pprint.setter
    def syscalls_to_not_pprint(self: DisplayMixin, value: list[int | str] | None) -> None:
        """Get the syscalls to not pretty print.

        Args:
            value (list[int | str] | None): The syscalls to not pretty print.
        """
        if value is None:
            self._internal_debugger.syscalls_to_not_pprint = None
        elif isinstance(value, list):
            self._internal_debugger.syscalls_to_not_pprint = [
                v if isinstance(v, int) else resolve_syscall_number(self._internal_debugger.arch, v) for v in value
            ]
        else:
            raise ValueError(
                "syscalls_to_not_pprint must be a list of integers or strings or None.",
            )
        if self._internal_debugger.pprint_syscalls:
            self._internal_debugger.enable_pretty_print()

    # Representation
    def __repr__(self: DisplayMixin) -> str:
        """Return the string representation of the `Debugger` object."""
        repr_str = "Debugger("
        repr_str += f"argv = {self._internal_debugger.argv}, "
        repr_str += f"path = {self._internal_debugger.path}, "
        repr_str += f"aslr = {self._internal_debugger.aslr_enabled}, "
        repr_str += f"env = {self._internal_debugger.env}, "
        repr_str += f"escape_antidebug = {self._internal_debugger.escape_antidebug}, "
        repr_str += f"continue_to_binary_entrypoint = {self._internal_debugger.autoreach_entrypoint}, "
        repr_str += f"auto_interrupt_on_command = {self._internal_debugger.auto_interrupt_on_command}, "
        repr_str += f"fast_memory = {self._internal_debugger.fast_memory}, "
        repr_str += f"kill_on_exit = {self._internal_debugger.kill_on_exit})\n"
        repr_str += f"follow_children = {self._internal_debugger.follow_children}, "
        repr_str += f"  Architecture: {self.arch}\n"
        repr_str += "  Threads:"
        for thread in self.threads:
            repr_str += f"\n    ({thread.tid}, {'dead' if thread.dead else 'alive'}) "
            repr_str += f"ip: {thread.instruction_pointer:#x}"
        return repr_str