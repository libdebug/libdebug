#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestSuite, TestLoader, TextTestRunner

from scripts.alias_test import AliasTest

def fast_suite():
    suite = TestSuite()

    suite.addTest(TestLoader().loadTestsFromTestCase(AliasTest))

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
