#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Roberto Alessandro Bertolini
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

from libdebug.architectures.amd64.amd64_stack_unwinder import (
    Amd64StackUnwinder,
)
from libdebug.architectures.stack_unwinding_manager import StackUnwindingManager
from libdebug.utils.libcontext import libcontext

_amd64_stack_unwinder = Amd64StackUnwinder()


def stack_unwinding_provider() -> StackUnwindingManager:
    """Returns an instance of the stack unwinding provider to be used by the `Debugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return _amd64_stack_unwinder
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
