#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger_holder import internal_debugger_holder

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


def get_global_internal_debugger() -> InternalDebugger:
    """Can be used to retrieve a temporarily-global internal debugger."""
    if internal_debugger_holder.global_internal_debugger is None:
        raise RuntimeError("No internal debugger available")
    return internal_debugger_holder.global_internal_debugger


def provide_internal_debugger(reference: object) -> InternalDebugger:
    """Provide a internal debugger.

    Args:
        reference (object): the object that needs the internal debugger.

    Returns:
        InternalDebugger: the internal debugger.
    """
    if reference in internal_debugger_holder.internal_debuggers:
        return internal_debugger_holder.internal_debuggers[reference]

    if internal_debugger_holder.global_internal_debugger is None:
        raise RuntimeError("No internal debugger available")

    internal_debugger_holder.internal_debuggers[reference] = internal_debugger_holder.global_internal_debugger
    return internal_debugger_holder.global_internal_debugger


def link_to_internal_debugger(reference: object, internal_debugger: InternalDebugger) -> None:
    """Link a reference to a InternalDebugger.

    Args:
        reference (object): the object that needs the internal debugger.
        internal_debugger (InternalDebugger): the internal debugger.
    """
    internal_debugger_holder.internal_debuggers[reference] = internal_debugger


@contextmanager
def extend_internal_debugger(referrer: object) -> ...:
    """Extend the internal debugger.

    Args:
        referrer (object): the referrer object.

    Yields:
        InternalDebugger: the internal debugger.
    """
    with internal_debugger_holder.internal_debugger_lock:
        if referrer not in internal_debugger_holder.internal_debuggers:
            raise RuntimeError("Referrer isn't linked to any internal debugger.")

        internal_debugger_holder.global_internal_debugger = internal_debugger_holder.internal_debuggers[referrer]
        yield
        internal_debugger_holder.global_internal_debugger = None
