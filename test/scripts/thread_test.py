#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE
from utils.thread_utils import FUN_RET_VAL

from libdebug import debugger


class ThreadTest(TestCase):
    def test_thread(self):
        d = debugger(RESOLVE_EXE("thread_test"))

        d.run()

        bp_t0 = d.breakpoint("do_nothing")
        bp_t1 = d.breakpoint("thread_1_function")
        bp_t2 = d.breakpoint("thread_2_function")
        bp_t3 = d.breakpoint("thread_3_function")

        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(150):
            if bp_t0.address == d.instruction_pointer:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if len(d.threads) > 1 and bp_t1.address == d.threads[1].instruction_pointer:
                t1_done = True
            if len(d.threads) > 2 and bp_t2.address == d.threads[2].instruction_pointer:
                t2_done = True
            if len(d.threads) > 3 and bp_t3.address == d.threads[3].instruction_pointer:
                t3_done = True

            d.cont()

        d.kill()
        d.terminate()

    def test_thread_hardware(self):
        d = debugger(RESOLVE_EXE("thread_test"))

        d.run()

        bp_t0 = d.breakpoint("do_nothing", hardware=True)
        bp_t1 = d.breakpoint("thread_1_function", hardware=True)
        bp_t2 = d.breakpoint("thread_2_function", hardware=True)
        bp_t3 = d.breakpoint("thread_3_function", hardware=True)

        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(15):
            if bp_t0.address == d.instruction_pointer:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if len(d.threads) > 1 and bp_t1.address == d.threads[1].instruction_pointer:
                t1_done = True
            if len(d.threads) > 2 and bp_t2.address == d.threads[2].instruction_pointer:
                t2_done = True
            if len(d.threads) > 3 and bp_t3.address == d.threads[3].instruction_pointer:
                t3_done = True

            d.cont()

        d.kill()
        d.terminate()

    def test_thread_complex(self):
        def factorial(n):
            if n == 0:
                return 1
            else:
                return (n * factorial(n - 1)) & (2**32 - 1)

        d = debugger(RESOLVE_EXE("thread_complex_test"))

        d.run()

        bp1_t0 = d.breakpoint("do_nothing")
        bp2_t1 = d.breakpoint("thread_1_function+17")
        bp3_t2 = d.breakpoint("thread_2_function+1e")

        bp1_hit, bp2_hit, bp3_hit = False, False, False
        t1, t2 = None, None

        d.cont()

        while True:
            if len(d.threads) == 2:
                t1 = d.threads[1]

            if len(d.threads) == 3:
                t2 = d.threads[2]

            if t1 and bp2_t1.address == t1.instruction_pointer:
                bp2_hit = True
                self.assertTrue(bp2_t1.hit_count == (FUN_RET_VAL(t1) + 1))

            if bp1_t0.address == d.instruction_pointer:
                bp1_hit = True
                self.assertTrue(bp2_hit)
                self.assertEqual(bp2_t1.hit_count, 50)
                self.assertFalse(bp3_hit)
                self.assertEqual(bp1_t0.hit_count, 1)

            if t2 and bp3_t2.address == t2.instruction_pointer:
                bp3_hit = True
                self.assertTrue(factorial(bp3_t2.hit_count) == FUN_RET_VAL(t2))
                self.assertTrue(bp2_hit)
                self.assertTrue(bp1_hit)

            d.cont()

            if bp3_t2.hit_count == 49:
                break

        d.kill()
        d.terminate()
