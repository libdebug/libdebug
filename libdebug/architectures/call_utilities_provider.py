#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.amd64.amd64_call_utilities import (
    Amd64CallUtilities,
)
from libdebug.architectures.call_utilities_manager import CallUtilitiesManager

_amd64_call_utilities = Amd64CallUtilities()

def call_utilities_provider(architecture: str) -> CallUtilitiesManager:
    """Returns an instance of the call utilities provider to be used by the `_InternalDebugger` class."""
    match architecture:
        case "amd64":
            return _amd64_call_utilities
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
