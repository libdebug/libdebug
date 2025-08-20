#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.state.thread_context import ThreadContext

if TYPE_CHECKING:
    from libdebug.architectures.aarch64.aarch64_ptrace_register_holder import (
        Aarch64PtraceRegisterHolder,
    )
    from libdebug.debugger.internal_debugger import InternalDebugger


class Aarch64ThreadContext(ThreadContext):
    """This object represents a thread in the context of the target aarch64 process. It holds information about the thread's state, registers and stack."""

    def __init__(
        self: Aarch64ThreadContext,
        thread_id: int,
        registers: Aarch64PtraceRegisterHolder,
        internal_debugger: InternalDebugger,
    ) -> None:
        """Initialize the thread context with the given thread id."""
        super().__init__(thread_id, registers, internal_debugger)

        # Register the thread properties
        self._register_holder.apply_on_thread(self, Aarch64ThreadContext)
