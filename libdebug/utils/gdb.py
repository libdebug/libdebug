#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2021-2024 Mario Polino.
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
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
