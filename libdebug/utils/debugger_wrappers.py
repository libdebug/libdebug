#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from functools import wraps


def control_flow_function(method):
    """Decorator to perfom control flow checks before executing a method."""

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # We have to ensure that the process is stopped before executing the method
        self._ensure_process_stopped()

        # We have to ensure that at least one thread is alive before executing the method
        if not self._threads_are_alive():
            raise RuntimeError("All threads are dead.")
        return method(self, *args, **kwargs)

    return wrapper


def background_alias(alias_method):
    """Decorator that automatically resolves the call to a different method if coming from the background thread."""

    # This is the stupidest thing I've ever seen. Why Python, why?
    def _background_alias(method):
        @wraps(method)
        def inner(self, *args, **kwargs):
            if self._is_in_background():
                return alias_method(self, *args, **kwargs)
            return method(self, *args, **kwargs)

        return inner

    return _background_alias
