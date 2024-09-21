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

    def __repr__(self: Registers) -> str:
        """Returns a string representation of the object."""
        repr_str = f"Aarch64Registers(thread_id={self._thread_id})"

        attributes = [attr for attr in Registers.__dict__ if attr in self._generic_regs]
        max_len = max(len(attr) for attr in attributes) + 1

        repr_str += "".join(f"\n\t{attr + ':':<{max_len}} {getattr(self, attr):#x}" for attr in attributes)

        return repr_str
