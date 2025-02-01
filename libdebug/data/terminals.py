#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass
from typing import ClassVar


@dataclass
class TerminalTypes:
    """Terminal class for launching terminal emulators with predefined commands."""

    terminals: ClassVar[dict[str, list[str]]] = {
        "gnome-terminal-server": ["gnome-terminal", "--tab", "--"],
        "konsole": ["konsole", "--new-tab", "-e"],
        "xterm": ["xterm", "-e"],
        "lxterminal": ["lxterminal", "-e"],
        "mate-terminal": ["mate-terminal", "--tab", "-e"],
        "tilix": ["tilix", "--action=app-new-session", "-e"],
        "kgx": ["kgx", "--tab", "-e"],
        "alacritty": ["alacritty", "-e"],
        "kitty": ["kitty", "-e"],
        "urxvt": ["urxvt", "-e"],
        "tmux: server": ["tmux", "split-window", "-h"],
        "xfce4-terminal": ["xfce4-terminal", "--tab", "-e"],
        "terminator": ["terminator", "--new-tab", "-e"],
        "ptyxis-agent": ["ptyxis-agent", "--tab", "-x"],
    }

    @staticmethod
    def get_command(terminal_name: str) -> list[str]:
        """Retrieve the command list for a given terminal emulator name.

        Args:
        terminal_name (str): the name of the terminal emulator.

        Returns:
        list[str]: the command list for the terminal emulator, or an empty list if not found.
        """
        return TerminalTypes.terminals.get(terminal_name, [])
