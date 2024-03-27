#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest
from time import perf_counter_ns

from libdebug import debugger


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
