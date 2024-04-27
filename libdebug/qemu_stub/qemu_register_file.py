#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


class QemuRegisterFile:
    """A class that represents the register file of the QEMU GDBstub."""

    internal_representation: bytes
    """The internal representation of the register file."""

    changed: bool
    """Whether the register file has been changed."""

    def __init__(self, register_file: bytes):
        self.internal_representation = register_file
        self.changed = False

    def clear(self):
        """Clear the register file."""
        self.internal_representation = b"\xff" * len(self.internal_representation)
        self.changed = True
