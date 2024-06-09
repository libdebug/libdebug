#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from libdebug.data.debugging_context_holder import global_debugging_holder

if TYPE_CHECKING:
    from libdebug.state.debugging_context import DebuggingContext


def debugging_context() -> DebuggingContext:
    """Can be used to retrieve a temporarily-global debugging context."""
    if global_debugging_holder.debugging_global_context is None:
        raise RuntimeError("No debugging context available")
    return global_debugging_holder.debugging_global_context


def provide_context(reference: object) -> DebuggingContext:
    """Provide a debugging context.

    Args:
        reference (object): the object that needs the debugging context.

    Returns:
        DebuggingContext: the debugging context.
    """
    if reference in global_debugging_holder.debugging_contexts:
        return global_debugging_holder.debugging_contexts[reference]

    if global_debugging_holder.debugging_global_context is None:
        raise RuntimeError("No debugging context available")

    global_debugging_holder.debugging_contexts[reference] = (
        global_debugging_holder.debugging_global_context
    )
    return global_debugging_holder.debugging_global_context


def link_context(reference: object, referrer: object = None) -> None:
    """Link a reference to a referrer.

    Args:
        reference (object): the object that needs the debugging context.
        referrer (object): the referrer object.
    """
    if referrer is not None:
        global_debugging_holder.debugging_contexts[reference] = (
            global_debugging_holder.debugging_contexts[referrer]
        )
    elif global_debugging_holder.debugging_global_context is not None:
        global_debugging_holder.debugging_contexts[reference] = (
            global_debugging_holder.debugging_global_context
        )
    else:
        raise RuntimeError("No debugging context available")


@contextmanager
def context_extend_from(referrer: object) -> ...:
    """Extend the debugging context.

    Args:
        referrer (object): the referrer object.

    Yields:
        DebuggingContext: the debugging context.
    """
    with global_debugging_holder.debugging_context_lock:
        if referrer not in global_debugging_holder.debugging_contexts:
            raise RuntimeError("Referrer isn't linked to any context.")

        global_debugging_holder.debugging_global_context = (
            global_debugging_holder.debugging_contexts[referrer]
        )
        yield
        global_debugging_holder.debugging_global_context = None
