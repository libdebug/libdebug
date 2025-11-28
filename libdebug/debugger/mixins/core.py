#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.debugger.mixins.base import EngineBoundMixin

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class DebuggerCoreMixin(EngineBoundMixin):
    """Core lifecycle glue shared by all debugger variants."""

    def __init__(self, internal_debugger: InternalDebugger) -> None:
        """Wire the internal debugger; prefer the public `debugger` factory."""
        self._internal_debugger = internal_debugger
        self._internal_debugger.start_up()
        super().__init__()
