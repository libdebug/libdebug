#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass, field
from threading import Lock
from weakref import WeakKeyDictionary


@dataclass
class InternalDebuggerHolder:
    """A holder for internal debuggers."""
    internal_debuggers: WeakKeyDictionary = field(default_factory=WeakKeyDictionary)
    global_internal_debugger = None
    internal_debugger_lock = Lock()


internal_debugger_holder = InternalDebuggerHolder()
