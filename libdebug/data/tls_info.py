#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.native.libdebug_debug_sym_parser import Symbol


@dataclass(frozen=True, slots=True)
class TLSInfo:
    """Information about a TLS symbol's location for a specific thread."""

    symbol: Symbol
    """The TLS symbol."""

    thread_id: int
    """The thread ID."""

    address: int | None
    """The resolved address, or None if resolution failed."""

    is_static_tls: bool
    """Whether this is static TLS (resolved) or dynamic TLS (needs __tls_get_addr)."""
