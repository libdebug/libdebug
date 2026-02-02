#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.architectures.aarch64.aarch64_tls_resolver import (
    Aarch64TLSResolver,
)
from libdebug.architectures.amd64.amd64_tls_resolver import (
    Amd64TLSResolver,
)
from libdebug.architectures.i386.i386_tls_resolver import (
    I386TLSResolver,
)
from libdebug.architectures.shared.tls_resolver import TLSResolver

_aarch64_tls_resolver = Aarch64TLSResolver()
_amd64_tls_resolver = Amd64TLSResolver()
_i386_tls_resolver = I386TLSResolver()


def tls_resolver_provider(architecture: str) -> TLSResolver:
    """Returns an instance of the TLS resolver for the specified architecture.

    Args:
        architecture: The target architecture name.

    Returns:
        A TLSResolverManager instance for the architecture.

    Raises:
        NotImplementedError: If the architecture is not supported.
    """
    match architecture:
        case "amd64":
            return _amd64_tls_resolver
        case "aarch64":
            return _aarch64_tls_resolver
        case "i386":
            return _i386_tls_resolver
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
