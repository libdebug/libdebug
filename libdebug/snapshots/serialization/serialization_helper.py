#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.snapshots.serialization.supported_serializers import SupportedSerializers

if TYPE_CHECKING:
    from libdebug.snapshots.snapshot import Snapshot


class SerializationHelper:
    """Helper class to serialize and deserialize snapshots."""

    def load(self: SerializationHelper, file_path: str) -> Snapshot:
        """Load a snapshot from a file.

        Args:
            file_path (str): The path to the file containing the snapshot.

        Returns:
            Snapshot: The loaded snapshot object.
        """
        if not file_path.endswith(".json"):
            liblog.warning("The target file doesn't have a JSON extension. The output will be assumed JSON.")

        # Future code can select the serializer
        # Currently, only JSON is supported
        serializer_type = SupportedSerializers.JSON

        serializer = serializer_type.serializer_class()

        return serializer.load(file_path)

    def save(self: SerializationHelper, snapshot: Snapshot, out_path: str) -> None:
        """Dump a snapshot to a file.

        Args:
            snapshot (Snapshot): The snapshot to be dumped.
            out_path (str): The path to the output file.
        """
        if not out_path.endswith(".json"):
            liblog.warning("The target file doesn't have a JSON extension. The output will be assumed JSON.")

        # Future code can select the serializer
        # Currently, only JSON is supported
        serializer_type = SupportedSerializers.JSON

        serializer = serializer_type.serializer_class()

        serializer.dump(snapshot, out_path)
