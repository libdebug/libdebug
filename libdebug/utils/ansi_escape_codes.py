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
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    STRIKE = "\033[9m"
    DEFAULT_COLOR = "\033[39m"
    RESET = "\033[0m"


class ANSIKeyboadStrings:
    """Class to define keyboard keys for the terminal."""

    ESCAPE_KEY = b"\x1b"
    UP_ARROW_KEY = ESCAPE_KEY + b"[A"
    DOWN_ARROW_KEY = ESCAPE_KEY + b"[B"
    RIGHT_ARROW_KEY = ESCAPE_KEY + b"[C"
    LEFT_ARROW_KEY = ESCAPE_KEY + b"[D"
    UP_ARROW_KEYPAD = ESCAPE_KEY + b"OA"
    DOWN_ARROW_KEYPAD = ESCAPE_KEY + b"OB"
    RIGHT_ARROW_KEYPAD = ESCAPE_KEY + b"OC"
    LEFT_ARROW_KEYPAD = ESCAPE_KEY + b"OD"
    ERASE_LINE = ESCAPE_KEY + b"[2K"

    @classmethod
    def get_longest_key_length(cls: ANSIKeyboadStrings) -> int:
        """Return the length of the longest key string."""
        return max(
            len(getattr(cls, attr))
            for attr in cls.__dict__
            if not attr.startswith("__") and isinstance(getattr(cls, attr), bytes)
        )


class ASCIICodes:
    """Class to define ASCII control codes for the terminal."""

    BELL = b"\x07"
    BACKSPACE = b"\x08"
    TAB = b"\x09"
    NEWLINE = b"\x0a"
    VERTICAL_TAB = b"\x0b"
    FORM_FEED = b"\x0c"
    CARRIAGE_RETURN = b"\x0d"
    ESCAPE = b"\x1b"
    DELETE = b"\x7f"
    CTRL_C = b"\x03"
    CTRL_D = b"\x04"


class ANSIPrivateModes:
    """Class to define private modes for the terminal.

    These are not standard ANSI escape codes, but are used by some terminals.
    """

    HIDE_CURSOR = ANSIKeyboadStrings.ESCAPE_KEY + b"[?25l"
    SHOW_CURSOR = ANSIKeyboadStrings.ESCAPE_KEY + b"[?25h"
