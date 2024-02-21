#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
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

from typing import Callable

from libdebug.architectures.amd64.amd64_ptrace_register_holder import (
    Amd64PtraceRegisterHolder,
)
from libdebug.data.register_holder import RegisterHolder
from libdebug.utils.libcontext import libcontext


def register_holder_provider(
    register_file: bytes,
    ptrace_setter: Callable[[bytes], None] = None,
) -> RegisterHolder:
    """Returns an instance of the register holder to be used by the `Debugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64PtraceRegisterHolder(register_file, ptrace_setter)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
