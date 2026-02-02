#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.architectures.shared.tls_resolver import TLSResolver
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.native.libdebug_debug_sym_parser import TLSModuleInfo
    from libdebug.state.thread_context import ThreadContext


class Aarch64TLSResolver(TLSResolver):
    """TLS resolver for the AArch64 architecture.

    On AArch64 Linux, TLS is accessed via the TPIDR_EL0 register.
    Uses variant 1 TLS layout (TLS data after thread pointer, positive offsets).
    """

    def get_tls_base(self: Aarch64TLSResolver, thread: ThreadContext) -> int | None:
        """Get the TPIDR_EL0 register value for a thread.

        Args:
            thread: The thread context.

        Returns:
            The TPIDR_EL0 value, or None if not available.
        """
        try:
            regs = thread.regs
            if hasattr(regs, "tpidr_el0"):
                return regs.tpidr_el0
        except (AttributeError, OSError) as e:
            liblog.debugger("Failed to get tpidr_el0: %s", e)
        return None

    def compute_tls_address(
        self: Aarch64TLSResolver,
        tls_base: int,
        tls_offset: int,
        _: TLSModuleInfo | None,
    ) -> int:
        """Compute TLS address using variant 1 layout (positive offsets).

        Args:
            tls_base: The TLS base address for the thread.
            tls_offset: The offset of the symbol within the TLS block.
            tls_module: Optional TLS module info (unused for variant 1).

        Returns:
            The computed address.
        """
        # Variant 1: TLS data is after the thread pointer
        return tls_base + tls_offset
