#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.state.thread_context import ThreadContext

from libdebug.architectures.register_helper import register_holder_provider

class ThreadSnapshot:
    """A class that represents a snapshot of a thread's state."""

    def __init__(self: ThreadSnapshot, thread: ThreadContext, snap_level: str = "registers") -> None:
        """Create a new thread snapshot.

        Args:
            thread (ThreadContext): The thread context to snapshot.
            snap_level (str, optional): The snapshot level. Defaults to "base".
        """
        self.thread = thread
        self.snap_level = snap_level
        
        match self.snap_level:
            case "base":
                self._snap_registers()
            case "full":
                self._snap_registers()
                self._snap_writable_memory()
            case _:
                raise ValueError(f"Invalid snapshot level: {self.snap_level}")
    
    def _snap_registers(self: ThreadSnapshot) -> None:
        """Snapshot internal registers."""
        self.regs = register_holder_provider(
            self.thread.debugger.arch,
            self.thread.regs.register_file,
            self.thread.regs.fp_register_file)

    def _snap_writable_memory(self: ThreadSnapshot) -> None:
        """Snapshot writable memory."""
        self.writable_memory = self.thread.writable_memory