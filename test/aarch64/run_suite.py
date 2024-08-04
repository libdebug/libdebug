#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestLoader, TestSuite, TextTestRunner

from scripts.attach_detach_test import AttachDetachTest
from scripts.auto_waiting_test import AutoWaitingTest
from scripts.backtrace_test import BacktraceTest
from scripts.basic_test import BasicTest
from scripts.basic_test_pie import BasicTestPie
from scripts.basic_test_hw import BasicTestHw
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest
from scripts.builtin_handler_test import BuiltinHandlerTest
from scripts.callback_test import CallbackTest
from scripts.catch_signal_test import CatchSignalTest
from scripts.control_flow_test import ControlFlowTest
from scripts.death_test import DeathTest
from scripts.finish_test import FinishTest
from scripts.floating_point_test import FloatingPointTest
from scripts.handle_syscall_test import HandleSyscallTest
from scripts.hijack_syscall_test import HijackSyscallTest
from scripts.jumpstart_test import JumpstartTest
from scripts.memory_test import MemoryTest
from scripts.signals_multithread_test import SignalMultithreadTest
from scripts.speed_test import SpeedTest
from scripts.thread_test_complex import ThreadTestComplex
from scripts.thread_test import ThreadTest
from scripts.watchpoint_test import WatchpointTest

def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(AttachDetachTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BacktraceTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTestPie))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTestHw))
    suite.addTest(TestLoader().loadTestsFromTestCase(BreakpointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BruteTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BuiltinHandlerTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(CallbackTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(CatchSignalTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(ControlFlowTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(DeathTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(FinishTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(FloatingPointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(HandleSyscallTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(HijackSyscallTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(JumpstartTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(MemoryTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(SignalMultithreadTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(SpeedTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(ThreadTestComplex))
    suite.addTest(TestLoader().loadTestsFromTestCase(ThreadTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(WatchpointTest))

    return suite


if __name__ == "__main__":
    if sys.version_info >= (3, 12):
        runner = TextTestRunner(verbosity=2, durations=3)
    else:
        runner = TextTestRunner(verbosity=2)

    suite = fast_suite()

    runner.run(suite)

    sys.exit(0)
