#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from unittest import TestLoader, TestSuite, TextTestRunner


def fast_suite():
    suite = TestSuite()
    return suite


if __name__ == "__main__":
    if sys.version_info >= (3, 12):
        runner = TextTestRunner(verbosity=2, durations=3)
    else:
        runner = TextTestRunner(verbosity=2)

    suite = fast_suite()

    runner.run(suite)

    sys.exit(0)
