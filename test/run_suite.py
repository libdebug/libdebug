#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestSuite, TestLoader, TextTestRunner

from scripts.alias_test import AliasTest
from scripts.attach_detach_test import AttachDetachTest
from scripts.auto_waiting_test import AutoWaitingTest
from scripts.auto_waiting_jumput_test import AutoWaitingJumpoutTest
from scripts.auto_waiting_nlinks_test import AutoWaitingNlinksTest
from scripts.backtrace_test import BacktraceTest
from scripts.control_flow_test import ControlFlowTest
from scripts.register_test import RegisterTest

def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(AliasTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AttachDetachTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingJumpoutTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingNlinksTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BacktraceTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(ControlFlowTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(RegisterTest))

    return suite

def full_suite():
    suite = fast_suite()

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
