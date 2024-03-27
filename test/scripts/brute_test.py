#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
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
                bp = d.breakpoint(0x1222, hardware=True)
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                d.wait()

                while bp.address == d.rip:
                    d.cont()
                    d.wait()

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


if __name__ == "__main__":
    unittest.main()
