#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from libdebug.data.tls_info import TLSInfo
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.native.libdebug_debug_sym_parser import Symbol, TLSModuleInfo
    from libdebug.state.thread_context import ThreadContext


class TLSResolver(ABC):
    """An architecture-independent interface for TLS resolution.

    TLS (Thread-Local Storage) resolution requires architecture-specific
    knowledge of how the TLS base pointer is accessed:
    - x86-64: FS segment register (variant 2: negative offsets)
    - i386: GS segment register (variant 2: negative offsets)
    - AArch64: TPIDR_EL0 register (variant 1: positive offsets)
    """

    @abstractmethod
    def get_tls_base(self: TLSResolver, thread: ThreadContext) -> int | None:
        """Get the TLS base address for a thread.

        Args:
            thread: The thread context.

        Returns:
            The TLS base address, or None if not available.
        """

    def compute_tls_address(
        self: TLSResolver,
        tls_base: int,
        tls_offset: int,
        tls_module: TLSModuleInfo | None,
    ) -> int:
        """Compute the TLS address from base, offset, and optional module info.

        Override this method for architectures with different TLS layouts.
        Default implementation uses variant 2 (x86 style: negative offsets).

        Args:
            tls_base: The TLS base address for the thread.
            tls_offset: The offset of the symbol within the TLS block.
            tls_module: Optional TLS module info with block size.

        Returns:
            The computed address.
        """
        if tls_module is not None:
            # Variant 2: TLS block is before thread pointer
            return tls_base - tls_module.tls_block_size + tls_offset
        # Fallback: simple offset
        return tls_base + tls_offset

    def resolve(
        self: TLSResolver,
        symbol: Symbol,
        thread: ThreadContext,
        tls_modules: dict,
    ) -> TLSInfo:
        """Resolve a TLS symbol to an address for a specific thread.

        Args:
            symbol: The TLS symbol to resolve.
            thread: The thread to resolve for.
            tls_modules: Dictionary mapping backing file paths to TLSModuleInfo.

        Returns:
            TLSInfo with the resolved address and metadata.
        """
        if not symbol.is_tls:
            return TLSInfo(
                symbol=symbol,
                thread_id=thread.tid,
                address=symbol.start,
                is_static_tls=False,
            )

        tls_base = self.get_tls_base(thread)
        if tls_base is None:
            liblog.warning(
                "Unable to get TLS base for thread %d, cannot resolve TLS symbol %s",
                thread.tid,
                symbol.name,
            )
            return TLSInfo(
                symbol=symbol,
                thread_id=thread.tid,
                address=None,
                is_static_tls=True,
            )

        tls_offset = symbol.tls_offset
        if tls_offset is None:
            return TLSInfo(
                symbol=symbol,
                thread_id=thread.tid,
                address=None,
                is_static_tls=True,
            )

        # Get TLS module info if available
        # First try backing_file, then reference_file for external debug symbols
        backing_file = symbol.backing_file
        tls_module = tls_modules.get(backing_file)

        # For external debug symbols, backing_file points to the debug file,
        # but TLS modules are indexed by the loaded ELF path (reference_file)
        if tls_module is None and symbol.is_external and symbol.reference_file:
            tls_module = tls_modules.get(symbol.reference_file)

        address = self.compute_tls_address(tls_base, tls_offset, tls_module)

        return TLSInfo(
            symbol=symbol,
            thread_id=thread.tid,
            address=address,
            is_static_tls=True,
        )
