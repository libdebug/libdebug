#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestLoader, TestSuite, TextTestRunner

from scripts.attach_detach_test import AttachDetachTest
from scripts.auto_waiting_test import AutoWaitingTest
from scripts.basic_test import BasicTest
from scripts.basic_test_pie import BasicTestPie
from scripts.basic_test_hw import BasicTestHw
from scripts.breakpoint_test import BreakpointTest
from scripts.brute_test import BruteTest

def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(AttachDetachTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(AutoWaitingTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTestPie))
    suite.addTest(TestLoader().loadTestsFromTestCase(BasicTestHw))
    suite.addTest(TestLoader().loadTestsFromTestCase(BreakpointTest))
    suite.addTest(TestLoader().loadTestsFromTestCase(BruteTest))

    return suite


if __name__ == "__main__":
    if sys.version_info >= (3, 12):
        runner = TextTestRunner(verbosity=2, durations=3)
    else:
        runner = TextTestRunner(verbosity=2)

    suite = fast_suite()

    runner.run(suite)

    sys.exit(0)
