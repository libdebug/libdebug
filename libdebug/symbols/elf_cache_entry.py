#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.native.libdebug_debug_sym_parser import Symbol, TLSModuleInfo


@dataclass
class ElfCacheEntry:
    """Cached information about a parsed ELF file."""

    symbols: list[Symbol] = field(default_factory=list)
    build_id: str | None = None
    debug_link: str | None = None
    is_pie: bool = False
    entry_point: int = 0
    tls_info: TLSModuleInfo | None = None
