#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE
from time import perf_counter_ns

from libdebug import debugger


class SpeedTest(TestCase):
    def setUp(self):
        self.d = debugger(RESOLVE_EXE("speed_test"))

    def test_speed(self):
        d = self.d

        start_time = perf_counter_ns()

        d.run()

        bp = d.breakpoint("do_nothing")

        d.cont()

        for _ in range(65536):
            self.assertTrue(bp.address == d.instruction_pointer)
            d.cont()

        d.kill()
        d.terminate()

        end_time = perf_counter_ns()

        self.assertTrue((end_time - start_time) < 15 * 1e9)  # 15 seconds

    def test_speed_hardware(self):
        d = self.d

        start_time = perf_counter_ns()

        d.run()

        bp = d.breakpoint("do_nothing", hardware=True)

        d.cont()

        for _ in range(65536):
            self.assertTrue(bp.address == d.instruction_pointer)
            d.cont()

        d.kill()
        d.terminate()

        end_time = perf_counter_ns()

        self.assertTrue((end_time - start_time) < 15 * 1e9)  # 15 seconds
