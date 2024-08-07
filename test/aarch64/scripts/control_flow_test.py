#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class ControlFlowTest(unittest.TestCase):
    def test_step_until_1(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint("main")
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(0x0000aaaaaaaa0854)

        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa0854)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_until_2(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint(0x7fc, hardware=True)
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(0x0000aaaaaaaa0854, max_steps=7)

        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa0818)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_until_3(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint(0x7fc)

        # Let's put some breakpoints in-between
        d.breakpoint(0x804)
        d.breakpoint(0x80c)
        d.breakpoint(0x808, hardware=True)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        # trace is [0x7fc, 0x800, 0x804, 0x808, 0x80c, 0x810, 0x814, 0x818]
        d.step_until(0x0000aaaaaaaa0854, max_steps=7)

        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa0818)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_and_cont(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa083c)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa0840)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_and_cont_hardware(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa083c)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa0840)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_until_and_cont(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(0x0000aaaaaaaa083c)

        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa083c)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_until_and_cont_hardware(self):
        d = debugger("binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(0x0000aaaaaaaa083c)
        self.assertTrue(d.regs.pc == 0x0000aaaaaaaa083c)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()