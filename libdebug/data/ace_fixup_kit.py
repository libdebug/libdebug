#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger import Debugger
    from libdebug.state.thread_context import ThreadContext


@dataclass(frozen=True)
class ACEFixupKit:
    """A class that provides a fixup kit for new processes and threads after arbitrary code execution."""

    register_dump: dict[str, int] = None
    """The register dump."""

    patch_address: int = 0
    """The address of the applied patch."""

    code_backup: bytes = b""
    """The code backup."""

    @staticmethod
    def create_fixup_kit(
        thread: ThreadContext,
        patch_address: int,
        code_backup: bytes,
    ) -> ACEFixupKit:
        """Create a fixup kit from the template of the given thread."""
        kit = ACEFixupKit(
            register_dump={},
            patch_address=patch_address,
            code_backup=code_backup,
        )
        # Fill the register dump with the current register values
        for reg_name in dir(thread.regs):
            if isinstance(getattr(thread.regs, reg_name), int | float) and reg_name != "_thread_id":
                kit.register_dump[reg_name] = getattr(thread.regs, reg_name)

    def fixup_thread(
        self: ACEFixupKit,
        thread: ThreadContext,
    ) -> None:
        """Fixup the new thread from the template."""
        # Restore the registers
        for reg_name, reg_value in self.register_dump.items():
            setattr(thread.regs, reg_name, reg_value)

    def fixup_process(
        self: ACEFixupKit,
        debugger: Debugger,
    ) -> None:
        """Fixup the new process from the template."""
        self.fixup_thread(debugger.threads[0])

        # Restore the code
        debugger.memory[self.patch_address : self.patch_address + len(self.code_backup)] = self.code_backup
