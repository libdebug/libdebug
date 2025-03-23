#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.state.thread_context import ThreadContext

if TYPE_CHECKING:
    from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
        Amd64PtraceRegisterHolder,
    )


class Amd64ThreadContext(ThreadContext):
    """This object represents a thread in the context of the target amd64 process. It holds information about the thread's state, registers and stack."""

    def __init__(self: Amd64ThreadContext, thread_id: int, registers: Amd64PtraceRegisterHolder) -> None:
        """Initialize the thread context with the given thread id."""
        super().__init__(thread_id, registers)

        # Register the thread properties
        self._register_holder.apply_on_thread(self, Amd64ThreadContext)

    @property
    def num_syscall_args(self: Amd64ThreadContext) -> int:
        """Returns the number of syscall arguments."""
        return 6
