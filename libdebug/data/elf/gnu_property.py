#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GNUProperty:
    """Represents a GNU Property parsed from a note in an ELF file."""

    pr_type: str
    """The type of the GNU property."""

    value: str | int | bytes
    """The data of the GNU property."""

