#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from enum import Enum


class AvailableInterfaces(Enum):
    """An enumeration of the available backend interfaces."""

    PTRACE = 1
