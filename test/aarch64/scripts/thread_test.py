#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class ThreadTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_thread(self):
        d = debugger("binaries/thread_test")

        d.run()

        bp_t0 = d.breakpoint("do_nothing")
        bp_t1 = d.breakpoint("thread_1_function")
        bp_t2 = d.breakpoint("thread_2_function")
        bp_t3 = d.breakpoint("thread_3_function")

        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(150):
            if bp_t0.address == d.regs.pc:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if len(d.threads) > 1 and bp_t1.address == d.threads[1].regs.pc:
                t1_done = True
            if len(d.threads) > 2 and bp_t2.address == d.threads[2].regs.pc:
                t2_done = True
            if len(d.threads) > 3 and bp_t3.address == d.threads[3].regs.pc:
                t3_done = True

            d.cont()

        d.kill()
        d.terminate()

    def test_thread_hardware(self):
        d = debugger("binaries/thread_test")

        d.run()

        bp_t0 = d.breakpoint("do_nothing", hardware=True)
        bp_t1 = d.breakpoint("thread_1_function", hardware=True)
        bp_t2 = d.breakpoint("thread_2_function", hardware=True)
        bp_t3 = d.breakpoint("thread_3_function", hardware=True)

        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(15):
            if bp_t0.address == d.regs.pc:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if len(d.threads) > 1 and bp_t1.address == d.threads[1].regs.pc:
                t1_done = True
            if len(d.threads) > 2 and bp_t2.address == d.threads[2].regs.pc:
                t2_done = True
            if len(d.threads) > 3 and bp_t3.address == d.threads[3].regs.pc:
                t3_done = True

            d.cont()

        d.kill()
        d.terminate()

if __name__ == "__main__":
    unittest.main()
