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
    from libdebug.state.thread_context import ThreadContext


class I386TLSResolver(TLSResolver):
    """TLS resolver for the i386 architecture.

    On i386 Linux, TLS is accessed via the GS segment register.
    The GS base points to the Thread Control Block (TCB).
    Uses variant 2 TLS layout (same as x86-64).
    """

    def get_tls_base(self: I386TLSResolver, thread: ThreadContext) -> int | None:
        """Get the GS base address for a thread.

        Args:
            thread: The thread context.

        Returns:
            The GS base address, or None if not available.
        """
        try:
            regs = thread.regs
            if hasattr(regs, "gs_base"):
                return regs.gs_base
        except (AttributeError, OSError) as e:
            liblog.debugger("Failed to get gs_base: %s", e)
        return None
