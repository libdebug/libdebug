#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

"""TLS (Thread-Local Storage) resolution for libdebug.

This module provides a high-level interface for TLS symbol resolution,
delegating to architecture-specific implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.shared.tls_resolver import TLSInfo
from libdebug.architectures.tls_resolver_provider import tls_resolver_provider

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.native.libdebug_debug_sym_parser import Symbol
    from libdebug.state.thread_context import ThreadContext


# Re-export TLSInfo for convenience
__all__ = ["TLSInfo", "TLSManager"]


class TLSManager:
    """High-level TLS (Thread-Local Storage) resolver.

    This class provides a convenient interface for resolving TLS symbols
    to actual memory addresses for specific threads. It automatically
    selects the correct architecture-specific implementation.

    Example:
        >>> resolver = TLSResolver(d._internal_debugger)
        >>> result = resolver.resolve(tls_symbol, thread)
        >>> if result.address:
        ...     print(f"TLS variable at {result.address:#x}")
    """

    def __init__(self, debugger: InternalDebugger) -> None:
        """Initialize the TLS resolver.

        Args:
            debugger: The internal debugger instance.
        """
        self._debugger = debugger
        self._resolver = tls_resolver_provider(debugger.arch)

    def resolve(
        self,
        symbol: Symbol,
        thread: ThreadContext | None = None,
    ) -> TLSInfo:
        """Resolve a TLS symbol to an address for a specific thread.

        Args:
            symbol: The TLS symbol to resolve.
            thread: The thread to resolve for. If None, uses the first thread.

        Returns:
            TLSInfo with the resolved address and metadata.
        """
        if thread is None:
            thread = self._debugger.threads[0]

        # Get TLS modules from symbol manager if available
        tls_modules = {}
        if hasattr(self._debugger, "_symbol_manager") and self._debugger._symbol_manager:
            tls_modules = self._debugger._symbol_manager._tls_modules

        return self._resolver.resolve(symbol, thread, tls_modules)

    def resolve_by_name(
        self,
        name: str,
        thread: ThreadContext | None = None,
    ) -> TLSInfo | None:
        """Resolve a TLS symbol by name.

        Args:
            name: The symbol name to resolve.
            thread: The thread to resolve for. If None, uses the first thread.

        Returns:
            TLSInfo if found, None otherwise.
        """
        symbols = self._debugger.symbols
        tls_symbols = [s for s in symbols if s.is_tls and s.name == name]

        if not tls_symbols:
            return None

        return self.resolve(tls_symbols[0], thread)

    def get_all_tls_addresses(
        self,
        thread: ThreadContext | None = None,
    ) -> list[TLSInfo]:
        """Get addresses for all TLS symbols for a specific thread.

        Args:
            thread: The thread to resolve for. If None, uses the first thread.

        Returns:
            List of TLSInfo for all TLS symbols.
        """
        if thread is None:
            thread = self._debugger.threads[0]

        symbols = self._debugger.symbols
        tls_symbols = [s for s in symbols if s.is_tls]

        return [self.resolve(sym, thread) for sym in tls_symbols]

    def get_tls_base(self, thread: ThreadContext | None = None) -> int | None:
        """Get the TLS base address for a thread.

        Args:
            thread: The thread to get the base for. If None, uses the first thread.

        Returns:
            The TLS base address, or None if not available.
        """
        if thread is None:
            thread = self._debugger.threads[0]

        return self._resolver.get_tls_base(thread)
