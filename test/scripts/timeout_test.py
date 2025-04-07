#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from time import perf_counter, sleep
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class TimeoutTest(TestCase):
    def test_infinite_loop_timeout(self):
        # We will run a program that goes into an infinite loop
        # and we set a 1 seconds timeout
        d = debugger(RESOLVE_EXE("infinite_loop_test"))

        start = perf_counter()

        r = d.run(timeout=1)

        d.cont()

        r.sendline(b"1")

        d.wait()

        end = perf_counter()

        d.kill()
        d.terminate()

        # The timeout is not exact, so we allow a 0.3 seconds margin
        self.assertLessEqual(end - start, 1.3)
        self.assertGreaterEqual(end - start, 1.0)

    def test_normal_execution_timeout(self):
        # We will run a program normally and add a timeout
        # to ensure that nothing goes wrong
        d = debugger(RESOLVE_EXE("basic_test"))

        r = d.run(timeout=1)

        d.cont()

        r.sendline(b"1")

        d.wait()

        d.kill()
        d.terminate()

    def test_callback_timeout(self):
        # We will run a program normally but with a blocking
        # callback. This will print a warning
        d = debugger(RESOLVE_EXE("basic_test"))

        r = d.run(timeout=2)

        def callback(_, __):
            sleep(2)

        d.bp("register_test", callback=callback)

        d.cont()

        d.wait()

        d.kill()
        d.terminate()

    def test_repeated_timeout(self):
        # We ensure that a timeout doesn't disrupt the next run
        # of the debugger
        d = debugger(RESOLVE_EXE("infinite_loop_test"))

        for _ in range(5):
            r = d.run(timeout=0.5)

            start = perf_counter()

            d.cont()
            r.sendline(b"1")
            d.wait()
            d.kill()

            end = perf_counter()
            self.assertLessEqual(end - start, 0.8)
            self.assertGreaterEqual(end - start, 0.5)

        d.terminate()
