#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Roberto Alessandro Bertolini.
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

from libdebug import debugger
from pwn import process
import unittest
import logging

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

        d.wait()

        self.assertTrue(d.rip == bp.address)

        d.cont()

        d.kill()


if __name__ == "__main__":
    unittest.main()
