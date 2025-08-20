#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import atexit
import os
import sys
from termios import TCSANOW, tcsetattr
from typing import TYPE_CHECKING
from weakref import ref

from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


_instanced_debuggers: set[ref[InternalDebugger]] = set()


def register_internal_debugger(debugger: InternalDebugger) -> None:
    """Register an internal debugger instance."""
    _instanced_debuggers.add(ref(debugger))

def remove_internal_debugger_refs(debugger: InternalDebugger) -> None:
    """Remove a reference to an internal debugger instance."""
    updated_debuggers = {d for d in _instanced_debuggers if d() is not None and d() is not debugger}
    _instanced_debuggers.clear()
    _instanced_debuggers.update(updated_debuggers)
    liblog.debugger("Removed internal debugger reference: %s", debugger)

def _cleanup_internal_debugger() -> None:
    """Cleanup the internal debugger."""
    for debugger_ref in _instanced_debuggers:
        debugger = debugger_ref()
        if debugger is None:
            continue

        # Restore the original stdin settings, just in case
        try:
            if debugger.stdin_settings_backup:
                tcsetattr(sys.stdin.fileno(), TCSANOW, debugger.stdin_settings_backup)
        except Exception as e:
            liblog.debugger(f"Error while restoring the original stdin settings: {e}")

        # The following logic MUST work in any situation. This includes scenarios where the polling thread is stuck
        # due to an endless callback, an unhandled exceptions that break the thread, a logic error in libdebug or a
        # race condition causing the thread to wait indefinitely for an event that will never occur.

        # The key idea here is that we cannot rely on the background threads (both polling and timeout threads),
        # as only the main thread is aware of the script termination or the user's control-C interruption.
        if debugger.instanced and debugger.kill_on_exit:
            if debugger.is_debugging:
                # We will leverage the fact that we are in the wrong thread but the same process to kill the debuggee
                # process without relying on the background thread.
                try:
                    os.kill(debugger.process_id, 9)
                except Exception as e:  # noqa: BLE001
                    liblog.debugger("Error while interrupting debuggee: %s", e)

            # Now we can try to terminate both the polling thread and the timeout thread, if any. Again, we cannot
            # trust them, so we just try to notify them that the process is terminating.
            try:
                debugger._atexit_terminate()
            except Exception as e:  # noqa: BLE001
                liblog.debugger("Error while terminating the internal debugger: %s", e)

    _instanced_debuggers.clear()


atexit.register(_cleanup_internal_debugger)
