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

#
# jumpout - challenge from SECCON CTF 2023
#

import unittest

from pwn import *

from libdebug import debugger


class Jumpout(unittest.TestCase):
    def setUp(self):
        pass

    def test_jumpout(self):
        flag = ""
        first = 0x55
        second = 0

        d = debugger("CTF/jumpout")

        r = d.run()

        bp1 = d.breakpoint(0x140B, hardware=True)
        bp2 = d.breakpoint(0x157C, hardware=True)

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            d.wait()
            if d.rip == bp1.address:
                second = d.r9
            elif d.rip == bp2.address:
                address = d.r13 + d.rbx
                third = int.from_bytes(d.memory[address, 1], "little")
                flag += chr((first ^ second ^ third ^ (bp2.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")


if __name__ == "__main__":
    unittest.main()
