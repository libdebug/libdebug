#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.utils.oop.alias import check_aliased_property

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint
    from libdebug.data.memory_map import MemoryMap
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.data.signal_catcher import SignalCatcher
    from libdebug.data.symbol import Symbol
    from libdebug.data.symbol_list import SymbolList
    from libdebug.data.syscall_handler import SyscallHandler
    from libdebug.debugger.debugger import IntrospectionMixin
    from libdebug.memory.abstract_memory_view import AbstractMemoryView
    from libdebug.state.thread_context import ThreadContext


class IntrospectionMixin:
    """Read-only accessors for debugger state."""

    def resolve_symbol(self: IntrospectionMixin, symbol: str, file: str = "binary") -> int:
        """Resolves the address of the specified symbol.

        Args:
            symbol (str): The symbol to resolve.
            file (str): The backing file to resolve the symbol in. Defaults to "binary"

        Returns:
            int: The address of the symbol.
        """
        return self._internal_debugger.resolve_symbol(symbol, file)

    @property
    def symbols(self: IntrospectionMixin) -> SymbolList[Symbol]:
        """Get the symbols of the process."""
        return self._internal_debugger.symbols

    @property
    def threads(self: IntrospectionMixin) -> list[ThreadContext]:
        """Get the list of threads in the process."""
        return self._internal_debugger.threads

    @property
    def breakpoints(self: IntrospectionMixin) -> dict[int, Breakpoint]:
        """Get the breakpoints set on the process."""
        return self._internal_debugger.breakpoints

    @property
    def children(self: IntrospectionMixin) -> list[IntrospectionMixin]:
        """Get the list of child debuggers."""
        return self._internal_debugger.children

    @property
    def handled_syscalls(self: IntrospectionMixin) -> dict[int, SyscallHandler]:
        """Get the handled syscalls dictionary.

        Returns:
            dict[int, SyscallHandler]: the handled syscalls dictionary.
        """
        return self._internal_debugger.handled_syscalls

    @property
    def caught_signals(self: IntrospectionMixin) -> dict[int, SignalCatcher]:
        """Get the caught signals dictionary.

        Returns:
            dict[int, SignalCatcher]: the caught signals dictionary.
        """
        return self._internal_debugger.caught_signals

    @property
    def maps(self: IntrospectionMixin) -> MemoryMapList[MemoryMap]:
        """Get the memory maps of the process."""
        return self._internal_debugger.maps

    @check_aliased_property("mem")
    def memory(self: IntrospectionMixin) -> AbstractMemoryView:
        """The memory view of the process."""
        return self._internal_debugger.memory

    @property
    def mem(self: IntrospectionMixin) -> AbstractMemoryView:
        """Alias for the `memory` property.

        The memory view of the process.
        """
        return self._internal_debugger.memory

    @check_aliased_property("pid")
    def process_id(self: IntrospectionMixin) -> int:
        """The process ID."""
        return self._internal_debugger.process_id

    @property
    def pid(self: IntrospectionMixin) -> int:
        """Alias for the `process_id` property.

        The process ID.
        """
        return self._internal_debugger.process_id

    @property
    def running(self: IntrospectionMixin) -> bool:
        """Whether the process is running."""
        return self._internal_debugger.running
