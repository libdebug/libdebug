#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from argparse import ArgumentParser
from unittest import TestSuite, TestLoader, TextTestRunner

import scripts


def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.AliasTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.AntidebugEscapingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.ArgumentListTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.AtexitHandlerTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.AttachDetachTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.AutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.BacktraceTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.BreakpointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.CallbackTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.ControlFlowTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.CorruptedELFTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.CursedBinariesTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.DeathTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.DebuggerArgumentTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.ElfApiTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.FindPointersTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.FinishTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.FloatingPointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.LargeBinarySymTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.MemoryTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.MemoryNoFastTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.MultipleDebuggersTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.MultiprocessingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.NextTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.NlinksTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.PPrintSyscallsTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.RegisterTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.RunPipesTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SignalCatchTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SignalMultithreadTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SnapshotsTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SymbolTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SyscallHandleTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SyscallHijackTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.ThreadTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.WatchpointTest))

    return suite

def full_suite():
    suite = fast_suite()

    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.BruteTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.DeepDiveDivisionTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.JumpoutTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.SpeedTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.TimeoutTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.Vmwhere1Test))

    return suite

def stress_suite():
    suite = TestSuite()

    for _ in range(1024):
        suite.addTest(TestLoader().loadTestsFromTestCase(scripts.ThreadTest))

    return suite

def memory_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(scripts.MemoryLeakTest))

    return suite

def main(suite: str):
    if sys.version_info >= (3, 12):
        runner = TextTestRunner(verbosity=2, durations=3)
    else:
        runner = TextTestRunner(verbosity=2)

    if suite == "slow":
        suite = full_suite()
    elif suite == "stress":
        suite = stress_suite()
        runner.verbosity = 1
    elif suite == "fast":
        suite = fast_suite()
    elif suite == "memory":
        suite = memory_suite()
    else:
        raise ValueError(f"Invalid suite: {suite}")

    runner.run(suite)

if __name__ == "__main__":
    parser = ArgumentParser(prog="libdebug Test Suite", description="Run the test suite")
    parser.add_argument("suite", type=str, help="The suite to run the tests from", choices=["fast", "slow", "stress", "memory"], default="fast", nargs="?")

    dbg = 'dbg' in sys.argv
    if dbg:
        sys.argv.remove('dbg')

    args = parser.parse_args()

    if dbg:
        sys.argv.append('dbg')

    main(args.suite)
