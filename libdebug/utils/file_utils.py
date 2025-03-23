#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import os
from pathlib import Path


@functools.cache
def ensure_file_executable(path: str) -> None:
    """Ensures that a file exists and is executable.

    Args:
        path (str): The path to the file.

    Throws:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file is not executable.
    """
    file = Path(path)

    if not file.exists():
        raise FileNotFoundError(f"File '{path}' does not exist.")

    if not file.is_file():
        raise FileNotFoundError(f"Path '{path}' is not a file.")

    if not os.access(file, os.X_OK):
        raise PermissionError(f"File '{path}' is not executable.")
