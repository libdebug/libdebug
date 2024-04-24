#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

#
# jumpout - challenge from SECCON CTF 2023
#

import unittest

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
