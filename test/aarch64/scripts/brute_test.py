#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import string
import unittest

from libdebug import debugger


class BruteTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_bruteforce(self):
        flag = ""
        counter = 1

        d = debugger("binaries/brute_test")

        while not flag or flag != "BRUTINOBRUTONE":
            for c in string.printable:
                r = d.run()
                bp = d.breakpoint(0x974, hardware=True, file="binary")
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                while bp.address == d.regs.pc:
                    d.cont()

                if bp.hit_count > counter:
                    flag += c
                    counter = bp.hit_count
                    d.kill()
                    break

                message = r.recvline()

                d.kill()

                if message == b"Giusto!":
                    flag += c
                    break

        self.assertEqual(flag, "BRUTINOBRUTONE")
