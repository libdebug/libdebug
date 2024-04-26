#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass


@dataclass
class QemuRegisterDefinition:
    """A class that holds the definition of a register of a process, specifically for the `qemu` debugging backend.

    Attributes:
        name (str): The name of the register.
        offset (int): The offset of the register in the register file.
        size (int): The size of the register in bytes.
    """

    name: str
    offset: int
    size: int
