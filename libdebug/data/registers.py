#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Registers(ABC):
    """Abtract class that holds the state of the architectural-dependent registers of a process."""

    @abstractmethod
    def __init__(self: Registers) -> None:
        """Initializes the Registers object."""
