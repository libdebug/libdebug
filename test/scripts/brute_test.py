#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini.
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
