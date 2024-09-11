#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import atexit
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


@dataclass
class InternalDebuggerHolder:
    """A holder for internal debuggers."""

    internal_debuggers: WeakKeyDictionary = field(default_factory=WeakKeyDictionary)
    global_internal_debugger = None
    internal_debugger_lock = Lock()


internal_debugger_holder = InternalDebuggerHolder()


def _cleanup_internal_debugger() -> None:
    """Cleanup the internal debugger."""
    for debugger in set(internal_debugger_holder.internal_debuggers.values()):
        debugger: InternalDebugger

        if debugger.instanced and debugger.kill_on_exit:
            try:
                debugger.interrupt()
            except Exception as e:
                liblog.debugger(f"Error while interrupting debuggee: {e}")

            try:
                debugger.terminate()
            except Exception as e:
                liblog.debugger(f"Error while terminating the debugger: {e}")


atexit.register(_cleanup_internal_debugger)
