#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import atexit
import os
import sys
import traceback
from dataclasses import dataclass, field
from termios import TCSANOW, tcsetattr
from threading import Lock
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from libdebug.liblog import liblog

try:
    from rich.console import Console
    from rich.traceback import Traceback
except ImportError:
    console = None
else:
    console = Console()


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

            # The background thread might have raised an exception that we are unaware of.
            # We want to capture it and notify the user. If the user has issued a Control-C, the traceback will be
            # printed after the one for the KeyboardInterrupt.
            try:
                debugger._check_status()
            except Exception as e:  # noqa: BLE001
                if console:
                    tb = Traceback.from_exception(
                        exc_type=type(e),
                        exc_value=e,
                        traceback=e.__traceback__,
                    )
                    console.print(tb)
                else:
                    traceback.print_exc()

            # Now we can try to terminate both the polling thread and the timeout thread, if any. Again, we cannot
            # trust them, so we just try to notify them that the process is terminating.
            try:
                debugger.atexit_terminate()
            except Exception as e:  # noqa: BLE001
                liblog.debugger("Error while terminating the internal debugger: %s", e)


atexit.register(_cleanup_internal_debugger)
