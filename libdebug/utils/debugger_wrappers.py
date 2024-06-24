#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.state.thread_context import ThreadContext


def change_state_function_process(method: callable) -> callable:
    """Decorator to perfom control flow checks before executing a method."""

    @wraps(method)
    def wrapper(self: InternalDebugger, *args: ..., **kwargs: ...) -> ...:
        if not self.instanced:
            raise RuntimeError(
                "Process not running. Did you call run()?",
            )

        # We have to ensure that the process is stopped before executing the method
        self._ensure_process_stopped()

        # We have to ensure that at least one thread is alive before executing the method
        if self.threads[0].dead:
            raise RuntimeError("All threads are dead.")
        return method(self, *args, **kwargs)

    return wrapper


def change_state_function_thread(method: callable) -> callable:
    """Decorator to perfom control flow checks before executing a method."""

    @wraps(method)
    def wrapper(
        self: InternalDebugger, thread: ThreadContext, *args: ..., **kwargs: ...
    ) -> ...:
        if not self.instanced:
            raise RuntimeError(
                "Process not running. Did you call run()?",
            )

        # We have to ensure that the process is stopped before executing the method
        self._ensure_process_stopped()

        # We have to ensure that at least one thread is alive before executing the method
        if thread.dead:
            raise RuntimeError("The threads is dead.")
        return method(self, thread, *args, **kwargs)

    return wrapper


def background_alias(alias_method: callable) -> callable:
    """Decorator that automatically resolves the call to a different method if coming from the background thread."""

    # This is the stupidest thing I've ever seen. Why Python, why?
    def _background_alias(method: callable) -> callable:
        @wraps(method)
        def inner(self: InternalDebugger, *args: ..., **kwargs: ...) -> ...:
            if self._is_in_background():
                return alias_method(self, *args, **kwargs)
            return method(self, *args, **kwargs)

        return inner

    return _background_alias
