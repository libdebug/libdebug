#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
import unittest

from scripts.attach_test import AttachTest
from scripts.auto_waiting_test import AutoWaitingTest, AutoWaitingNcuts
from scripts.backtrace_test import BacktraceTest
from scripts.basic_test import BasicPieTest, BasicTest, ControlFlowTest, HwBasicTest
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest
from scripts.callback_test import CallbackTest
from scripts.jumpout import Jumpout
from scripts.large_binary_sym_test import LargeBinarySymTest
from scripts.memory_test import MemoryTest
from scripts.multiple_debuggers_test import MultipleDebuggersTest
from scripts.ncuts import Ncuts
from scripts.non_waiting_test import NonWaitingTest, NonWaitingNcuts
from scripts.speed_test import SpeedTest
from scripts.thread_test import ComplexThreadTest, ThreadTest
from scripts.vmwhere1 import Vmwhere1
from scripts.watchpoint_test import WatchpointTest
from scripts.watchpoint_alias_test import WatchpointAliasTest


def fast_suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest("test_basic"))
    suite.addTest(BasicTest("test_registers"))
    suite.addTest(BasicTest("test_step"))
    suite.addTest(BasicTest("test_step_hardware"))
    suite.addTest(BasicPieTest("test_basic"))
    suite.addTest(BreakpointTest("test_bps"))
    suite.addTest(BreakpointTest("test_bp_disable"))
    suite.addTest(BreakpointTest("test_bp_disable_hw"))
    suite.addTest(BreakpointTest("test_bp_disable_reenable"))
    suite.addTest(BreakpointTest("test_bp_disable_reenable_hw"))
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
    suite.addTest(LargeBinarySymTest("test_large_binary_symbol_load_times"))
    suite.addTest(LargeBinarySymTest("test_large_binary_demangle"))
    suite.addTest(NonWaitingTest("test_bps_non_waiting"))
    suite.addTest(NonWaitingTest("test_jumpout_non_waiting"))
    suite.addTest(NonWaitingNcuts("test_ncuts"))
    suite.addTest(AutoWaitingTest("test_bps_auto_waiting"))
    suite.addTest(AutoWaitingTest("test_jumpout_auto_waiting"))
    suite.addTest(AutoWaitingNcuts("test_ncuts"))
    suite.addTest(WatchpointTest("test_watchpoint"))
    suite.addTest(WatchpointAliasTest("test_watchpoint_alias"))
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
