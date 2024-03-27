#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import logging
import unittest

from pwn import process

from libdebug import debugger

logging.getLogger("pwnlib").setLevel(logging.ERROR)


class AttachTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_attach(self):
        r = process("binaries/attach_test")

        d = debugger("binaries/attach_test")
        d.attach(r.pid)
        bp = d.breakpoint("printName", hardware=True)
        d.cont()

        r.recvuntil(b"name:")
        r.sendline(b"Io_no")

        self.assertTrue(d.rip == bp.address)

        d.cont()

        d.kill()


if __name__ == "__main__":
    unittest.main()
