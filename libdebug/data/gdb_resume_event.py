#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class GdbResumeEvent:
    """This class handles the actions needed to resume the debugging session, after returning from GDB."""

    def __init__(
        self: GdbResumeEvent,
        internal_debugger: InternalDebugger,
        lambda_function: callable[[], None],
    ) -> None:
        """Initializes the GdbResumeEvent.

        Args:
            internal_debugger (InternalDebugger): The internal debugger instance.
            lambda_function (callable[[], None]): The blocking lambda function to wait on.
        """
        self._internal_debugger = internal_debugger
        self._lambda_function = lambda_function
        self._joined = False

    def join(self: GdbResumeEvent) -> None:
        """Resumes the debugging session, blocking the script until GDB terminate and libdebug reattaches."""
        if self._joined:
            raise RuntimeError("GdbResumeEvent already joined")

        self._lambda_function()
        self._internal_debugger._resume_from_gdb()
        self._joined = True
