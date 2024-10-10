#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

ARCH_MAPPING = {
    "i686": "i386",
    "x86": "i386",
    "x86_64": "amd64",
    "x64": "amd64",
    "arm64": "aarch64",
}


def map_arch(arch: str) -> str:
    """Map the architecture to the correct format.

    Args:
        arch (str): the architecture to map.

    Returns:
        str: the mapped architecture.
    """
    arch = arch.lower()

    if arch in ARCH_MAPPING.values():
        return arch
    elif arch in ARCH_MAPPING:
        return ARCH_MAPPING[arch]
    else:
        raise ValueError(f"Architecture {arch} not supported.")
