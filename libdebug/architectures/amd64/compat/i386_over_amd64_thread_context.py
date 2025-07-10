#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.state.thread_context import ThreadContext

if TYPE_CHECKING:
    from libdebug.architectures.amd64.compat.i386_over_amd64_ptrace_register_holder import (
        I386OverAMD64PtraceRegisterHolder,
    )


class I386OverAMD64ThreadContext(ThreadContext):
    """This object represents a thread in the context of the target i386 process when running on amd64. It holds information about the thread's state, registers and stack."""

    def __init__(
        self: I386OverAMD64ThreadContext,
        thread_id: int,
        registers: I386OverAMD64PtraceRegisterHolder,
    ) -> None:
        """Initialize the thread context with the given thread id."""
        super().__init__(thread_id, registers)

        # Register the thread properties
        self._register_holder.apply_on_thread(self, I386OverAMD64ThreadContext)
