#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import ClassVar


class TerminalTypes:
    """Terminal class for launching terminal emulators."""

    gnome_terminal_server: ClassVar[list[str]] = ["gnome-terminal", "--tab", "--"]
    konsole: ClassVar[list[str]] = ["konsole", "--new-tab", "-e"]
    xterm: ClassVar[list[str]] = ["xterm", "-e"]
    lxterminal: ClassVar[list[str]] = ["lxterminal", "-e"]
    mate_terminal: ClassVar[list[str]] = ["mate-terminal", "--tab", "-e"]
    tilix: ClassVar[list[str]] = ["tilix", "--action=app-new-session", "-e"]
    kgx: ClassVar[list[str]] = ["kgx", "--tab", "-e"]
    alacritty: ClassVar[list[str]] = ["alacritty", "-e"]
    kitty: ClassVar[list[str]] = ["kitty", "-e"]
    urxvt: ClassVar[list[str]] = ["urxvt", "-e"]
    tmux_server: ClassVar[list[str]] = ["tmux", "split-window", "-h"]
    xfce4_terminal: ClassVar[list[str]] = ["xfce4-terminal", "--tab", "-e"]
    terminator: ClassVar[list[str]] = ["terminator", "--new-tab", "-e"]
