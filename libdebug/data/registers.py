#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger


@dataclass
class Registers:
    """Abtract class that holds the state of the architectural-dependent registers of a process."""

    def __init__(self: Registers, thread_id: int) -> None:
        """Initializes the Registers object."""
        self._internal_debugger = get_global_internal_debugger()
        self._thread_id = thread_id
