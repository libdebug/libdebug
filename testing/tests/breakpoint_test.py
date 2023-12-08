#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini, Gabriele Digregorio.
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
        self.exceptions = []

    def test_bps(self):
        def bp_random_function(d, bp):
            try:
                self.assertTrue(d.rip == 0x401136)
            except Exception as e:
                self.exceptions.append(e)

        global counter
        counter = 1

        def bp_loop(d, bp):
            try:
                global counter
                self.assertTrue(bp.hit_count == counter)
                counter += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_loop_end(d, bp):
            try:
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b("random_function", bp_random_function)
        self.d.b(0x401154, bp_loop)
        self.d.b(0x401166, bp_loop_end)
        self.d.cont()
        self.d.kill()
        self.assertTrue(True)
        if self.exceptions:
            raise self.exceptions[0]

if __name__ == '__main__':
    unittest.main()