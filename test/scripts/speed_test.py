#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
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
from time import perf_counter_ns


class SpeedTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/speed_test")

    def test_speed(self):
        d = self.d

        start_time = perf_counter_ns()

        d.run()

        bp = d.breakpoint("do_nothing")

        d.cont()

        for _ in range(65536):
            d.wait()
            self.assertTrue(bp.address == d.rip)
            d.cont()

        d.kill()

        end_time = perf_counter_ns()

        self.assertTrue((end_time - start_time) < 15 * 1e9)  # 15 seconds

    def test_speed_hardware(self):
        d = self.d

        start_time = perf_counter_ns()

        d.run()

        bp = d.breakpoint("do_nothing", hardware=True)

        d.cont()

        for _ in range(65536):
            d.wait()
            self.assertTrue(bp.address == d.rip)
            d.cont()

        d.kill()

        end_time = perf_counter_ns()

        self.assertTrue((end_time - start_time) < 15 * 1e9)  # 15 seconds


if __name__ == "__main__":
    unittest.main()
