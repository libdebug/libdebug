#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


def get_platform_register_size(arch: str) -> int:
    """Get the register size of the platform.

    Args:
        arch (str): The architecture of the platform.

    Returns:
        int: The register size in bytes.
    """
    match arch:
        case "amd64":
            return 8
        case "aarch64":
            return 8
        case _:
            raise ValueError(f"Architecture {arch} not supported.")
