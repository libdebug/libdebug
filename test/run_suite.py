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

import subprocess
import unittest

from scripts.attach_test import AttachTest
from scripts.backtrace_test import BacktraceTest
from scripts.basic_test import BasicPieTest, BasicTest, HwBasicTest
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest
from scripts.callback_test import CallbackTest
from scripts.jumpout import Jumpout
from scripts.memory_test import MemoryTest
from scripts.ncuts import Ncuts
from scripts.speed_test import SpeedTest
from scripts.thread_test import ThreadTest, ComplexThreadTest
from scripts.vmwhere1 import Vmwhere1


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest("test_basic"))
    suite.addTest(BasicTest("test_registers"))
    suite.addTest(BasicTest("test_step"))
    suite.addTest(BasicTest("test_step_hardware"))
    suite.addTest(BasicPieTest("test_basic"))
    suite.addTest(BreakpointTest("test_bps"))
    suite.addTest(MemoryTest("test_memory"))
    # suite.addTest(MemoryTest("test_mem_access_libs"))
    suite.addTest(MemoryTest("test_memory_exceptions"))
    suite.addTest(HwBasicTest("test_basic"))
    suite.addTest(HwBasicTest("test_registers"))
    suite.addTest(BacktraceTest("test_backtrace"))
    suite.addTest(BruteTest("test_bruteforce"))
    suite.addTest(Vmwhere1("test_vmwhere1"))
    suite.addTest(Jumpout("test_jumpout"))
    suite.addTest(Ncuts("test_ncuts"))
    suite.addTest(AttachTest("test_attach"))
    suite.addTest(ThreadTest("test_thread"))
    suite.addTest(ThreadTest("test_thread_hardware"))
    suite.addTest(ComplexThreadTest("test_thread"))
    suite.addTest(CallbackTest("test_callback_simple"))
    suite.addTest(CallbackTest("test_callback_simple_hardware"))
    suite.addTest(CallbackTest("test_callback_memory"))
    suite.addTest(CallbackTest("test_callback_bruteforce"))
    suite.addTest(CallbackTest("test_callback_jumpout"))
    suite.addTest(CallbackTest("test_callback_intermixing"))
    suite.addTest(SpeedTest("test_speed"))
    suite.addTest(SpeedTest("test_speed_hardware"))
    return suite


def profiling():
    command = "py-spy record --format speedscope -o ./python_profiling.app -- python scripts/node.py"
    result = subprocess.run(command, shell=True)

    if result.returncode == 0:
        print("Python profiling executed successfully!")
    else:
        print("Error occurred during python profiling. Return code:", result.returncode)


if __name__ == "__main__":
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

    # profiling()
