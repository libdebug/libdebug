#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.snapshots.snapshot import Snapshot


class AbstractSerializer(ABC):
    """Helper class to serialize and deserialize snapshots."""

    @abstractmethod
    def load(self: AbstractSerializer, file_path: str) -> Snapshot:
        """Load a snapshot from a file.

        Args:
            file_path (str): The path to the file containing the snapshot.

        Returns:
            Snapshot: The loaded snapshot object.
        """

    @abstractmethod
    def dump(self: AbstractSerializer, snapshot: Snapshot, out_path: str) -> None:
        """Dump a snapshot to a file.

        Args:
            snapshot (Snapshot): The snapshot to be dumped.
            out_path (str): The path to the output file.
        """

