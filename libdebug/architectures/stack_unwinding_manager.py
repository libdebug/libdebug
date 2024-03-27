#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class StackUnwindingManager:
    """
    An architecture-independent interface for stack unwinding.
    """

    def unwind(self, target: "ThreadContext"):
        """
        Unwind the stack of the target process.
        """
        pass
