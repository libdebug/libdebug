#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from libdebug.snapshots.serialization.json_serializer import JSONSerializer

if TYPE_CHECKING:
    from libdebug.snapshots.serialization.serializer import Serializer


class SupportedSerializers(Enum):
    """Enumeration of supported serializers for snapshots."""
    JSON = JSONSerializer

    @property
    def serializer_class(self: SupportedSerializers) -> Serializer:
        """Return the serializer class."""
        return self.value
