#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from dataclasses import dataclass

from libdebug.data.register_holder import RegisterHolder
from libdebug.qemu_stub.qemu_register_definition import QemuRegisterDefinition


@dataclass
class QemuRegisterHolder(RegisterHolder):
    """An abstract class that holds the state of the registers of a process, specifically for the `qemu` debugging backend.

    This class should not be instantiated directly, but rather through the `register_holder_provider` function.

    Attributes:
        register_file (object): The content of the register file of the process, as returned by the QEMU GDBstub.
        register_definitions (list[QemuRegisterDefinition]): The definition of the registers of the target architecture.
    """

    register_file: object
    endianness: str
    register_definitions: list[QemuRegisterDefinition]
