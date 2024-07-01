#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys
from contextlib import contextmanager
from copy import deepcopy

from libdebug.liblog import liblog


class LibContext:
    """A class that holds the global context of the library."""

    _instance = None

    def __new__(cls: type):
        """Create a new instance of the class if it does not exist yet.

        Returns:
            LibContext: the instance of the class.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self: LibContext) -> None:
        """Initializes the context."""
        if self._initialized:
            return

        self._sym_lvl = 3

        self._debugger_logger = "INFO"
        self._pipe_logger = "INFO"
        self._general_logger = "INFO"

        # Adjust log levels based on command-line arguments
        if len(sys.argv) > 1:
            if "debugger" in sys.argv:
                liblog.debugger_logger.setLevel("DEBUG")
                self._debugger_logger = "DEBUG"
            elif "pipe" in sys.argv:
                liblog.pipe_logger.setLevel("DEBUG")
                self._pipe_logger = "DEBUG"
            elif "dbg" in sys.argv:
                self._set_debug_level_for_all()
                self._debugger_logger = "DEBUG"
                self._pipe_logger = "DEBUG"
                self._general_logger = "DEBUG"
        self._initialized = True

        self._arch = "amd64"
        self._terminal = []

    def _set_debug_level_for_all(self: LibContext) -> None:
        """Set the debug level for all the loggers to DEBUG."""
        for logger in [
            liblog.general_logger,
            liblog.debugger_logger,
            liblog.pipe_logger,
        ]:
            logger.setLevel("DEBUG")

    @property
    def sym_lvl(self: LibContext) -> int:
        """Property getter for sym_lvl.

        Returns:
            _sym_lvl (int): the current symbol level.
        """
        return self._sym_lvl

    @sym_lvl.setter
    def sym_lvl(self: LibContext, value: int) -> None:
        """Property setter for sym_lvl, ensuring it's between 0 and 5."""
        if 0 <= value <= 5:
            self._sym_lvl = value
        else:
            raise ValueError("sym_lvl must be between 0 and 5")

    @property
    def debugger_logger(self: LibContext) -> str:
        """Property getter for debugger_logger.

        Returns:
            _debugger_logger (str): the current debugger logger level.
        """
        return self._debugger_logger

    @debugger_logger.setter
    def debugger_logger(self: LibContext, value: str) -> None:
        """Property setter for debugger_logger, ensuring it's a valid logging level."""
        if value in ["DEBUG", "INFO"]:
            self._debugger_logger = value
            liblog.debugger_logger.setLevel(value)
        else:
            raise ValueError("debugger_logger must be a valid logging level")

    @property
    def pipe_logger(self: LibContext) -> str:
        """Property getter for pipe_logger.

        Returns:
            _pipe_logger (str): the current pipe logger level.
        """
        return self._pipe_logger

    @pipe_logger.setter
    def pipe_logger(self: LibContext, value: str) -> None:
        """Property setter for pipe_logger, ensuring it's a valid logging level."""
        if value in ["DEBUG", "INFO"]:
            self._pipe_logger = value
            liblog.pipe_logger.setLevel(value)
        else:
            raise ValueError("pipe_logger must be a valid logging level")

    @property
    def general_logger(self: LibContext) -> str:
        """Property getter for general_logger.

        Returns:
            _general_logger (str): the current general logger level.
        """
        return self._general_logger

    @general_logger.setter
    def general_logger(self: LibContext, value: str) -> None:
        """Property setter for general_logger, ensuring it's a valid logging level."""
        if value in ["DEBUG", "INFO"]:
            self._general_logger = value
            liblog.general_logger.setLevel(value)
        else:
            raise ValueError("general_logger must be a valid logging level")

    @property
    def arch(self: LibContext) -> str:
        """Property getter for architecture.

        Returns:
            _arch (str): the current architecture.
        """
        return self._arch

    @arch.setter
    def arch(self: LibContext, value: str) -> None:
        """Property setter for arch, ensuring it's a valid architecture."""
        if value in ["amd64"]:
            self._arch = value
        else:
            raise RuntimeError("The specified architecture is not supported")

    @property
    def terminal(self: LibContext) -> list[str]:
        """Property getter for terminal.

        Returns:
            _terminal (str): the current terminal.
        """
        return self._terminal

    @terminal.setter
    def terminal(self: LibContext, value: list[str] | str) -> None:
        """Property setter for terminal, ensuring it's a valid terminal."""
        if isinstance(value, str):
            value = [value]

        self._terminal = value

    def update(self: LibContext, **kwargs: ...) -> None:
        """Update the context with the given values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @contextmanager
    def tmp(self: LibContext, **kwargs: ...) -> ...:
        """Context manager that temporarily changes the library context. Use "with" statement."""
        # Make a deep copy of the current state
        old_context = deepcopy(self.__dict__)
        self.update(**kwargs)
        try:
            yield
        finally:
            # Restore the original state
            self.__dict__.update(old_context)
            liblog.debugger_logger.setLevel(self.debugger_logger)
            liblog.pipe_logger.setLevel(self.pipe_logger)


# Global context instance
libcontext = LibContext()
