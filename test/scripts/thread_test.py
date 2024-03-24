#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
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

        t1, t2, t3 = None, None, None
        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(150):
            d.wait()

            if len(d.threads) == 2:
                t1 = d.threads[1]
            if len(d.threads) == 3:
                t2 = d.threads[2]
            if len(d.threads) == 4:
                t3 = d.threads[3]

            if bp_t0.address == d.rip:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if t1 and bp_t1.address == t1.rip:
                t1_done = True
            if t2 and bp_t2.address == t2.rip:
                t2_done = True
            if t3 and bp_t3.address == t3.rip:
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

        t1, t2, t3 = None, None, None
        t1_done, t2_done, t3_done = False, False, False

        d.cont()

        for _ in range(15):
            d.wait()

            # TODO: This is a workaround for the fact that the threads are not kept around after they die
            if len(d.threads) == 2:
                t1 = d.threads[1]
            if len(d.threads) == 3:
                t2 = d.threads[2]
            if len(d.threads) == 4:
                t3 = d.threads[3]

            if bp_t0.address == d.rip:
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break

            if t1 and bp_t1.address == t1.rip:
                t1_done = True
            if t2 and bp_t2.address == t2.rip:
                t2_done = True
            if t3 and bp_t3.address == t3.rip:
                t3_done = True

            d.cont()

        d.kill()
        d.terminate()


class ComplexThreadTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_thread(self):
        def factorial(n):
            if n == 0:
                return 1
            else:
                return (n * factorial(n - 1)) & (2**32 - 1)

        d = d = debugger("binaries/complex_thread_test")

        d.run()

        bp1_t0 = d.breakpoint("do_nothing")
        bp2_t1 = d.breakpoint("thread_1_function+17")
        bp3_t2 = d.breakpoint("thread_2_function+1e")

        bp1_hit, bp2_hit, bp3_hit = False, False, False
        t1, t2 = None, None

        d.cont()

        while True:
            d.wait()

            if len(d.threads) == 2:
                t1 = d.threads[1]

            if len(d.threads) == 3:
                t2 = d.threads[2]

            if t1 and bp2_t1.address == t1.rip:
                bp2_hit = True
                self.assertTrue(bp2_t1.hit_count == (t1.rax + 1))

            if bp1_t0.address == d.rip:
                bp1_hit = True
                self.assertTrue(bp2_hit)
                self.assertEqual(bp2_t1.hit_count, 50)
                self.assertFalse(bp3_hit)
                self.assertEqual(bp1_t0.hit_count, 1)

            if t2 and bp3_t2.address == t2.rip:
                bp3_hit = True
                self.assertTrue(factorial(bp3_t2.hit_count) == t2.rax)
                self.assertTrue(bp2_hit)
                self.assertTrue(bp1_hit)

            d.cont()

            if bp3_t2.hit_count == 49:
                break

        d.kill()
        d.terminate()


if __name__ == "__main__":
    unittest.main()
