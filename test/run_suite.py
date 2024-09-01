#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestSuite, TestLoader, TextTestRunner

from scripts.alias_test import AliasTest
from scripts.antidebug_escaping_test import AntidebugEscapingTest
from scripts.attach_detach_test import AttachDetachTest
from scripts.auto_waiting_test import AutoWaitingTest
from scripts.backtrace_test import BacktraceTest
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest
from scripts.callback_test import CallbackTest
from scripts.control_flow_test import ControlFlowTest
from scripts.death_test import DeathTest
from scripts.deep_dive_division_test import DeepDiveDivisionTest
from scripts.finish_test import FinishTest
from scripts.floating_point_test import FloatingPointTest
from scripts.jumpout_test import JumpoutTest
from scripts.jumpout_auto_waiting_test import JumpoutAutoWaitingTest
from scripts.jumpstart_test import JumpstartTest
from scripts.large_binary_sym_test import LargeBinarySymTest
from scripts.memory_test import MemoryTest
from scripts.multiple_debuggers_test import MultipleDebuggersTest
from scripts.next_test import NextTest
from scripts.nlinks_test import NlinksTest
from scripts.nlinks_auto_waiting_test import NlinksAutoWaitingTest
from scripts.pprint_syscalls_test import PPrintSyscallsTest
from scripts.register_test import RegisterTest
from scripts.signal_catch_test import SignalCatchTest
from scripts.syscall_handle_test import SyscallHandleTest
from scripts.syscall_hijack_test import SyscallHijackTest

def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(AliasTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AntidebugEscapingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AttachDetachTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BacktraceTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BreakpointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(CallbackTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(ControlFlowTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(DeathTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(FinishTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(FloatingPointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(JumpstartTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(LargeBinarySymTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(MemoryTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(MultipleDebuggersTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(NextTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(NlinksTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(NlinksAutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(PPrintSyscallsTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(RegisterTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(SignalCatchTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(SyscallHandleTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(SyscallHijackTest))

    return suite

def full_suite():
    suite = fast_suite()

    suite.addTest(TestLoader().loadTestsFromTestCase(BruteTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(DeepDiveDivisionTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(JumpoutTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(JumpoutAutoWaitingTest))

    return suite

def stress_suite():
    suite = TestSuite()

    return suite

def main():
    if sys.version_info >= (3, 12):
        runner = TextTestRunner(verbosity=2, durations=3)
    else:
        runner = TextTestRunner(verbosity=2)

    if len(sys.argv) > 1 and sys.argv[1].lower() == "slow":
        suite = full_suite()
    elif len(sys.argv) > 1 and sys.argv[1].lower() == "stress":
        suite = stress_suite()
        runner.verbosity = 1
    else:
        suite = fast_suite()

    runner.run(suite)

if __name__ == "__main__":
    main()
