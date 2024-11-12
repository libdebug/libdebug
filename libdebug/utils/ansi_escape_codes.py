#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class ANSIColors:
    """Class to define colors for the terminal."""

    RED = "\033[91m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    YELLOW = "\033[33m"
    PINK = "\033[95m"
    CYAN = "\033[96m"
    ORANGE = "\033[38;5;208m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    STRIKE = "\033[9m"
    DEFAULT_COLOR = "\033[39m"
    RESET = "\033[0m"
