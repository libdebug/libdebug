#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os


POSIX_SPAWN_CLOSE = 0
POSIX_SPAWN_DUP2 = 1
POSIX_SPAWN_OPEN = 2


def posix_spawn(file, argv, env, file_actions, setpgroup):
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
