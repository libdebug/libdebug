#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os

POSIX_SPAWN_CLOSE = 0
POSIX_SPAWN_DUP2 = 1
POSIX_SPAWN_OPEN = 2


def posix_spawn(file: str, argv: list, env: dict, file_actions: list, setpgroup: bool) -> int:
    """Spawn a new process, emulating the POSIX spawn function."""
    child_pid = os.fork()
    if child_pid == 0:
        for element in file_actions:
            if element[0] == POSIX_SPAWN_CLOSE:
                os.close(element[1])
            elif element[0] == POSIX_SPAWN_DUP2:
                os.dup2(element[1], element[2])
            elif element[0] == POSIX_SPAWN_OPEN:
                fd, path, flags, mode = element[1:]
                os.dup2(os.open(path, flags, mode), fd)
            else:
                raise ValueError("Invalid file action")
        if setpgroup == 0:
            os.setpgid(0, 0)
        os.execve(file, argv, env)

    return child_pid
