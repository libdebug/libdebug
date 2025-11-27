#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class DebuggerCoreMixin:
    """Core lifecycle glue shared by all debugger variants."""

    _sentinel: object = object()
    """A sentinel object."""

    _internal_debugger: InternalDebugger
    """The internal debugger object."""

    _previous_argv: list[str]
    """A copy of the previous argv state, used internally to detect changes to argv[0]."""

    def __init__(self, internal_debugger: InternalDebugger) -> None:
        """Wire the internal debugger; prefer the public `debugger` factory."""
        self._internal_debugger = internal_debugger
        self._internal_debugger.start_up()
        super().__init__()
