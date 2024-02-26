#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
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

import unittest

from libdebug import debugger


class BreakpointTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger('binaries/breakpoint_test')

    def test_bps(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115b)
        bp3 = d.breakpoint(0x40116d)

        counter = 1

        d.cont()

        while True:
            d.wait()

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                counter += 1
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                break

            d.cont()

        self.d.kill()

if __name__ == '__main__':
    unittest.main()
