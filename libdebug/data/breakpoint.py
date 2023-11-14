#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from dataclasses import dataclass
from typing import Callable, Self

@dataclass
class Breakpoint:
    """A breakpoint in the target process.

    Attributes:
        address (int): The address of the breakpoint in the target process.
        symbol (bytes): The symbol, if available, of the breakpoint in the target process.
        hit_count (int): The number of times this specific breakpoint has been hit.
        hardware (bool): Whether the breakpoint is a hardware breakpoint or not.
    """

    address: int = 0
    symbol: bytes = b""
    hit_count: int = 0
    hardware: bool = False
    _callback: None | Callable[['Debugger', Self], None] = None
