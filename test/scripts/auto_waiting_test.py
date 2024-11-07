#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


class AutoWaitingTest(TestCase):
    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_bps_auto_waiting_amd64(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"), auto_interrupt_on_command=False)

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        d.kill()
        d.terminate()
