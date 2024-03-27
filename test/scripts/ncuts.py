#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

#
# ncuts - challenge from DEF CON CTF Quals 2023
# Thanks to the whole mhackeroni CTF team for the exploit
#

import unittest

from libdebug import debugger


class Ncuts(unittest.TestCase):
    def setUp(self):
        pass

    def get_passsphrase_from_class_1_binaries(self, previous_flag):
        flag = b""

        d = debugger("CTF/1")
        r = d.run()

        bp = d.breakpoint(0x7EF1, hardware=True)

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        for _ in range(8):
            d.wait()

            self.assertTrue(d.rip == bp.address)

            offset = ord("a") ^ d.rbp
            d.rbp = d.r13
            flag += (offset ^ d.r13).to_bytes(1, "little")

            d.cont()

        r.recvline()

        d.kill()

        self.assertEqual(flag, b"\x00\x006\x00\x00\x00(\x00")
        return flag

    def get_passsphrase_from_class_2_binaries(self, previous_flag):
        bitmap = {}
        lastpos = 0
        flag = b""

        d = debugger("CTF/2")
        r = d.run()

        bp1 = d.breakpoint(0xD8C1, hardware=True)
        bp2 = d.breakpoint(0x1858, hardware=True)
        bp3 = d.breakpoint(0xDBA1, hardware=True)

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        while True:
            d.wait()

            if d.rip == bp1.address:
                lastpos = d.rbp
                d.rbp = d.r13 + 1
            elif d.rip == bp2.address:
                bitmap[d.r12 & 0xFF] = lastpos & 0xFF
            elif d.rip == bp3.address:
                d.rbp = d.r13
                wanted = d.rbp
                needed = 0
                for i in range(8):
                    if wanted & (2**i):
                        needed |= bitmap[2**i]
                flag += chr(needed).encode()

                if bp3.hit_count == 8:
                    d.cont()
                    break

            d.cont()

        d.kill()

        self.assertEqual(flag, b"\x00\x00\x00\x01\x00\x00a\x00")

    def get_passsphrase_from_class_3_binaries(self):
        flag = b""

        d = debugger("CTF/0")
        r = d.run()

        bp = d.breakpoint(0x91A1, hardware=True)

        d.cont()

        r.send(b"a" * 8)

        for _ in range(8):
            d.wait()

            self.assertTrue(d.rip == bp.address)

            offset = ord("a") - d.rbp
            d.rbp = d.r13

            flag += chr((d.r13 + offset) % 256).encode("latin-1")

            d.cont()

        r.recvline()

        d.kill()

        self.assertEqual(flag, b"BM8\xd3\x02\x00\x00\x00")
        return flag

    def test_ncuts(self):
        flag = self.get_passsphrase_from_class_3_binaries()
        flag = self.get_passsphrase_from_class_1_binaries(flag)
        self.get_passsphrase_from_class_2_binaries(flag)


if __name__ == "__main__":
    unittest.main()
