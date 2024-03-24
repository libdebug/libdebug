#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2021 - 2024 Mario Polino.
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini, Gabriele Digregorio.
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

import gdb

# To enable this command you need to source this file from a gdb console or a gdbinit script
# "source /path/to/this/file.py"


class GoBack(gdb.Command):
    def __init__(self):
        super(GoBack, self).__init__(
            "goback", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE, True
        )

    def invoke(self, args, from_tty):
        gdb.execute("detach")
        gdb.execute("quit")


GoBack()
