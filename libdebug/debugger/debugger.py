#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.debugger.mixins.breakpoints import BreakpointMixin
from libdebug.debugger.mixins.configuration import ConfigurationMixin
from libdebug.debugger.mixins.core import DebuggerCoreMixin
from libdebug.debugger.mixins.display import DisplayMixin
from libdebug.debugger.mixins.execution import ExecutionMixin
from libdebug.debugger.mixins.gdb import GdbMixin
from libdebug.debugger.mixins.introspection import IntrospectionMixin
from libdebug.debugger.mixins.snapshot import SnapshotMixin
from libdebug.debugger.mixins.thread_state import ThreadStateMixin


class Debugger(
    DebuggerCoreMixin,
    ExecutionMixin,
    BreakpointMixin,
    GdbMixin,
    ConfigurationMixin,
    IntrospectionMixin,
    ThreadStateMixin,
    DisplayMixin,
    SnapshotMixin,
):
    """Main libdebug debugger composed of mixins.

    The constructor expects an `InternalDebugger` instance; end users should keep using
    the `libdebug.debugger(...)` factory. Advanced users can subclass and add their own
    mixins to extend behaviour, provided their `__init__` forwards the `InternalDebugger`
    to `super().__init__`. If a mixin adds its own `__init__`, make it cooperative by
    calling `super().__init__()` (no arguments) so later mixins still run.
    """
