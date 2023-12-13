#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

import logging
import unittest
from scripts.basic_test import BasicTest, BasicPieTest, HwBasicTest
from scripts.breakpoint_test import BreakpointTest
from scripts.memory_test import MemoryTest
from scripts.backtrace_test import BacktraceTest
from scripts.brute_test import BruteTest
from scripts.vmwhere1 import Vmwhere1
from scripts.jumpout import Jumpout
from scripts.ncuts import Ncuts


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest("test_basic"))
    suite.addTest(BasicTest("test_registers"))
    suite.addTest(BasicPieTest("test_basic"))
    suite.addTest(BreakpointTest("test_bps"))
    suite.addTest(MemoryTest("test_memory"))
    suite.addTest(MemoryTest("test_mem_access_libs"))
    suite.addTest(HwBasicTest("test_basic"))
    suite.addTest(HwBasicTest("test_registers"))
    suite.addTest(BacktraceTest("test_backtrace"))
    suite.addTest(BruteTest("test_bruteforce"))
    suite.addTest(Vmwhere1("test_vmwhere1"))
    suite.addTest(Jumpout("test_jumpout"))
    suite.addTest(Ncuts("test_ncuts"))
    return suite


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    runner = unittest.TextTestRunner()
    result = runner.run(suite())
    
    if result.wasSuccessful():
        print("All tests passed")
    else:
        print("Some tests failed")
        print("\nFailed Tests:")
        for test, err in result.failures:
            print(f"{test}: {err}")
        print("\nErrors:")
        for test, err in result.errors:
            print(f"{test}: {err}")
