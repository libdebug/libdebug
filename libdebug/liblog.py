#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import logging

from libdebug.utils.print_style import PrintStyle


class LibLog:
    """Custom logger singleton class that can be used to log messages to the console."""

    _instance = None

    def __new__(cls: type):
        """Create a new instance of the class if it does not exist yet.

        Returns:
            LibLog: the instance of the class.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self: LibLog) -> None:
        """Initializes the logger."""
        if self._initialized:
            return

        # General logger
        self.general_logger = self._setup_logger("libdebug", logging.INFO)

        # Component-specific loggers
        self.debugger_logger = self._setup_logger("debugger", logging.INFO)
        self.pipe_logger = self._setup_logger("pipe", logging.INFO)

        self._initialized = True

    def _setup_logger(self: LibLog, name: str, level: int) -> logging.Logger:
        """Setup a logger with the given name and level.

        Args:
            name (str): name of the logger.
            level (int): logging level.

        Returns:
            logging.Logger: the logger object.
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def debugger(self: LibLog, message: str, *args: str, **kwargs: str) -> None:
        """Log a message to the debugger logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """
        header = f"[{PrintStyle.RED}DEBUGGER{PrintStyle.DEFAULT_COLOR}]"
        self.debugger_logger.debug(f"{header} {message}", *args, **kwargs)

    def pipe(self: LibLog, message: str, *args: str, **kwargs: str) -> None:
        """Log a message to the pipe logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """
        header = f"[{PrintStyle.BLUE}PIPE{PrintStyle.DEFAULT_COLOR}]"
        self.pipe_logger.debug(f"{header} {message}", *args, **kwargs)

    def info(self: LibLog, message: str, *args: str, **kwargs: str) -> None:
        """Log a info message to the general logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """
        header = f"[{PrintStyle.GREEN}INFO{PrintStyle.DEFAULT_COLOR}]"
        self.general_logger.info(f"{header} {message}", *args, **kwargs)

    def warning(self: LibLog, message: str, *args: str, **kwargs: str) -> None:
        """Log a warning message to the general logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """
        header = f"[{PrintStyle.BRIGHT_YELLOW}WARNING{PrintStyle.DEFAULT_COLOR}]"
        self.general_logger.warning(f"{header} {message}", *args, **kwargs)

    def error(self: LibLog, message: str, *args: str, **kwargs: str) -> None:
        """Log an error message to the general logger.

        Args:
            message (str): the message to log.
            *args: positional arguments to pass to the logger.
            **kwargs: keyword arguments to pass to the logger.
        """
        header = f"[{PrintStyle.RED}ERROR{PrintStyle.DEFAULT_COLOR}]"
        self.general_logger.error(f"{header} {message}", *args, **kwargs)


# Create the logger instance
liblog = LibLog()
