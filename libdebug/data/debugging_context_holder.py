#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass
from threading import Lock
from weakref import WeakKeyDictionary


@dataclass
class DebuggingContextHolder:
    debugging_contexts: WeakKeyDictionary = WeakKeyDictionary()
    debugging_global_context = None
    debugging_context_lock = Lock()


global_debugging_holder = DebuggingContextHolder()
