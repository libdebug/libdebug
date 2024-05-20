#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BreakpointTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/breakpoint_test")

    def test_bps(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 10)

        self.d.kill()

    def test_bp_disable(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 1)

        self.d.kill()

    def test_bp_disable_hw(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B, hardware=True)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        d.kill()

        self.assertEqual(bp2.hit_count, 1)

    def test_bp_disable_reenable(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp4 = d.breakpoint(0x401162)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        self.d.kill()

    def test_bp_disable_reenable_hw(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp4 = d.breakpoint(0x401162, hardware=True)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:

            if d.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.rsi == 45)
                self.assertTrue(d.esi == 45)
                self.assertTrue(d.si == 45)
                self.assertTrue(d.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        self.d.kill()


if __name__ == "__main__":
    unittest.main()
