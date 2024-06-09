#
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug import _InternalDebugger
    from libdebug.state.thread_context import ThreadContext


class ThreadList(list):
    def __init__(self: ThreadList, debugger: _InternalDebugger, *args: ThreadContext):
        super().__init__(*args)
        # Reference to the debugger class instance
        self.debugger = debugger

    def __getitem__(self, index: int):
        # Ensure the process is stopped before accessing the thread list
        self.debugger._ensure_process_stopped()
        return super().__getitem__(index)
