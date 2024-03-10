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

import sys
import unittest

from scripts.attach_test import AttachTest
from scripts.backtrace_test import BacktraceTest
from scripts.basic_test import BasicPieTest, BasicTest, ControlFlowTest, HwBasicTest
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest
from scripts.callback_test import CallbackTest
from scripts.jumpout import Jumpout
from scripts.memory_test import MemoryTest
from scripts.multiple_debuggers_test import MultipleDebuggersTest
from scripts.ncuts import Ncuts
from scripts.speed_test import SpeedTest
from scripts.thread_test import ComplexThreadTest, ThreadTest
from scripts.vmwhere1 import Vmwhere1


def fast_suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest("test_basic"))
    suite.addTest(BasicTest("test_registers"))
    suite.addTest(BasicTest("test_step"))
    suite.addTest(BasicTest("test_step_hardware"))
    suite.addTest(BasicPieTest("test_basic"))
    suite.addTest(BreakpointTest("test_bps"))
    suite.addTest(MemoryTest("test_memory"))
    suite.addTest(MemoryTest("test_mem_access_libs"))
    suite.addTest(MemoryTest("test_memory_exceptions"))
    suite.addTest(HwBasicTest("test_basic"))
    suite.addTest(HwBasicTest("test_registers"))
    suite.addTest(BacktraceTest("test_backtrace"))
    suite.addTest(AttachTest("test_attach"))
    suite.addTest(ThreadTest("test_thread"))
    suite.addTest(ThreadTest("test_thread_hardware"))
    suite.addTest(ComplexThreadTest("test_thread"))
    suite.addTest(CallbackTest("test_callback_simple"))
    suite.addTest(CallbackTest("test_callback_simple_hardware"))
    suite.addTest(CallbackTest("test_callback_memory"))
    suite.addTest(CallbackTest("test_callback_jumpout"))
    suite.addTest(CallbackTest("test_callback_intermixing"))
    suite.addTest(Jumpout("test_jumpout"))
    suite.addTest(Ncuts("test_ncuts"))
    suite.addTest(ControlFlowTest("test_step_until_1"))
    suite.addTest(ControlFlowTest("test_step_until_2"))
    suite.addTest(ControlFlowTest("test_step_until_3"))
    suite.addTest(ControlFlowTest("test_step_and_cont"))
    suite.addTest(ControlFlowTest("test_step_and_cont_hardware"))
    suite.addTest(ControlFlowTest("test_step_until_and_cont"))
    suite.addTest(ControlFlowTest("test_step_until_and_cont_hardware"))
    suite.addTest(MultipleDebuggersTest("test_multiple_debuggers"))
    return suite


def complete_suite():
    suite = fast_suite()
    suite.addTest(Vmwhere1("test_vmwhere1"))
    suite.addTest(Vmwhere1("test_vmwhere1_callback"))
    suite.addTest(BruteTest("test_bruteforce"))
    suite.addTest(CallbackTest("test_callback_bruteforce"))
    suite.addTest(SpeedTest("test_speed"))
    suite.addTest(SpeedTest("test_speed_hardware"))
    return suite


def thread_stress_suite():
    suite = unittest.TestSuite()
    for _ in range(1024):
        suite.addTest(ThreadTest("test_thread"))
        suite.addTest(ThreadTest("test_thread_hardware"))
        suite.addTest(ComplexThreadTest("test_thread"))
    return suite


if __name__ == "__main__":
    if sys.version_info >= (3, 12):
        runner = unittest.TextTestRunner(verbosity=2, durations=3)
    else:
        runner = unittest.TextTestRunner(verbosity=2)

    if len(sys.argv) > 1 and sys.argv[1].lower() == "slow":
        suite = complete_suite()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "thread_stress":
        suite = thread_stress_suite()
        runner.verbosity = 1
    else:
        suite = fast_suite()

    result = runner.run(suite)

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
