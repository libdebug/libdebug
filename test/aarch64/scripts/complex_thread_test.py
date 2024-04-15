#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class ComplexThreadTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_thread(self):
        def factorial(n):
            if n == 0:
                return 1
            else:
                return (n * factorial(n - 1)) & (2**32 - 1)

        d = debugger("binaries/complex_thread_test")

        d.run()

        bp1_t0 = d.breakpoint("do_nothing")
        bp2_t1 = d.breakpoint("thread_1_function+28")
        bp3_t2 = d.breakpoint("thread_2_function+24")

        bp1_hit, bp2_hit, bp3_hit = False, False, False
        t1, t2 = None, None

        d.cont()

        while True:
            if len(d.threads) == 2:
                t1 = d.threads[1]

            if len(d.threads) == 3:
                t2 = d.threads[2]

            if t1 and bp2_t1.address == t1.pc:
                bp2_hit = True
                self.assertTrue(bp2_t1.hit_count == t1.w0)

            if bp1_t0.address == d.pc:
                bp1_hit = True
                self.assertTrue(bp2_hit)
                self.assertEqual(bp2_t1.hit_count, 50)
                self.assertFalse(bp3_hit)
                self.assertEqual(bp1_t0.hit_count, 1)

            if t2 and bp3_t2.address == t2.pc:
                bp3_hit = True
                self.assertTrue(factorial(bp3_t2.hit_count) == t2.w0)
                self.assertTrue(bp2_hit)
                self.assertTrue(bp1_hit)

            d.cont()

            if bp3_t2.hit_count == 49:
                break

        d.kill()
        d.terminate()
