#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.commlink.libterminal import LibTerminal


class StdWrapper:
    """Wrapper around stderr/stdout to allow for custom write method."""

    def __init__(self: StdWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StderrWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def write(self, payload: bytes | str) -> int:
        """Overloads the write method to allow for custom behavior."""
        return self._terminal._write_manager(payload)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)
