#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger
from libdebug.architectures.aarch64.aarch64_thread_context import ThreadContextAarch64


class BasicTest(unittest.TestCase):
    def test_basic(self):
        d = debugger("binaries/basic_test")
        d.run()
        bp = d.breakpoint("register_test")
        d.cont()
        self.assertTrue(bp.address == d.pc)
        d.cont()
        d.kill()

    def test_registers(self):
        d = debugger("binaries/basic_test")

        d.run()

        bp = d.breakpoint(0x964)

        d.cont()

        self.assertTrue(bp.address == d.pc)

        self.assertTrue(d.x0 == 0x1111111111111111)
        self.assertTrue(d.x1 == 0x2222222222222222)
        self.assertTrue(d.x2 == 0x3333333333333333)
        self.assertTrue(d.x3 == 0x4444444444444444)
        self.assertTrue(d.x4 == 0x5555555555555555)
        self.assertTrue(d.x5 == 0x6666666666666666)
        self.assertTrue(d.x6 == 0x7777777777777777)
        self.assertTrue(d.x7 == 0x8888888888888888)
        self.assertTrue(d.x8 == 0x9999999999999999)
        self.assertTrue(d.x9 == 0xaaaaaaaaaaaaaaaa)
        self.assertTrue(d.x10 == 0xbbbbbbbbbbbbbbbb)
        self.assertTrue(d.x11 == 0xcccccccccccccccc)
        self.assertTrue(d.x12 == 0xdddddddddddddddd)
        self.assertTrue(d.x13 == 0xeeeeeeeeeeeeeeee)
        self.assertTrue(d.x14 == 0xffffffffffffffff)
        self.assertTrue(d.x15 == 0x0101010101010101)
        self.assertTrue(d.x16 == 0x0202020202020202)
        self.assertTrue(d.x17 == 0x0303030303030303)
        self.assertTrue(d.x18 == 0x0404040404040404)
        self.assertTrue(d.x19 == 0x0505050505050505)
        self.assertTrue(d.x20 == 0x0606060606060606)
        self.assertTrue(d.x21 == 0x0707070707070707)
        self.assertTrue(d.x22 == 0x0808080808080808)
        self.assertTrue(d.x23 == 0x0909090909090909)
        self.assertTrue(d.x24 == 0x0a0a0a0a0a0a0a0a)
        self.assertTrue(d.x25 == 0x0b0b0b0b0b0b0b0b)
        self.assertTrue(d.x26 == 0x0c0c0c0c0c0c0c0c)
        self.assertTrue(d.x27 == 0x0d0d0d0d0d0d0d0d)
        self.assertTrue(d.x28 == 0x0e0e0e0e0e0e0e0e)
        self.assertTrue(d.x29 == 0x0f0f0f0f0f0f0f0f)
        self.assertTrue(d.x30 == 0x1010101010101010)

        d.kill()

    def test_step(self):
        d = debugger("binaries/basic_test")

        d.run()
        bp = d.breakpoint("register_test")
        d.cont()

        self.assertTrue(bp.address == d.pc)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 4 == d.pc)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 8 == d.pc)
        self.assertTrue(bp.hit_count == 1)

        self.assertIsInstance(d.threads[0], ThreadContextAarch64)

        d.cont()
        d.kill()


if __name__ == "__main__":
    unittest.main()
