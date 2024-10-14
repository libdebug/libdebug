#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.aarch64.aarch64_call_utilities import (
    Aarch64CallUtilities,
)
from libdebug.architectures.amd64.amd64_call_utilities import (
    Amd64CallUtilities,
)
from libdebug.architectures.call_utilities_manager import CallUtilitiesManager
from libdebug.architectures.i386.i386_call_utilities import (
    I386CallUtilities,
)

_aarch64_call_utilities = Aarch64CallUtilities()
_amd64_call_utilities = Amd64CallUtilities()
_i386_call_utilities = I386CallUtilities()


def call_utilities_provider(architecture: str) -> CallUtilitiesManager:
    """Returns an instance of the call utilities provider to be used by the `_InternalDebugger` class."""
    match architecture:
        case "amd64":
            return _amd64_call_utilities
        case "aarch64":
            return _aarch64_call_utilities
        case "i386":
            return _i386_call_utilities
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
