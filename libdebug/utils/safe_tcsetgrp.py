#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


import os
from signal import SIG_IGN, SIGTTOU, signal


def safe_tcsetpgrp(fd: int, pgid: int) -> None:
    """A safe wrapper around `os.tcsetpgrp` that temporarily ignores `SIGTTOU`.

    This is useful when the calling process is not in the foreground process group of
    the terminal, such as when libdebug spawns a child process without redirecting
    its pipes. In that case, the terminal is assigned to the child's process group
    to ensure it can receive input from stdin, which can cause `tcsetpgrp` calls
    from the parent to trigger `SIGTTOU`.
    """
    old = signal(SIGTTOU, SIG_IGN)
    try:
        os.tcsetpgrp(fd, pgid)
    finally:
        signal(SIGTTOU, old)
