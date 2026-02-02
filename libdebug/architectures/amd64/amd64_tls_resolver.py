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


class Amd64TLSResolver(TLSResolver):
    """TLS resolver for the x86-64 architecture.

    On x86-64 Linux, TLS is accessed via the FS segment register.
    The FS base points to the Thread Control Block (TCB).
    Static TLS variables are stored at negative offsets from FS base.
    """

    def get_tls_base(self: Amd64TLSResolver, thread: ThreadContext) -> int | None:
        """Get the FS base address for a thread.

        Args:
            thread: The thread context.

        Returns:
            The FS base address, or None if not available.
        """
        try:
            regs = thread.regs
            if hasattr(regs, "fs_base"):
                return regs.fs_base
        except (AttributeError, OSError) as e:
            liblog.debugger("Failed to get fs_base: %s", e)
        return None
