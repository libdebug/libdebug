#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger
from libdebug.architectures.i386.i386_thread_context import ThreadContextI386


class BasicTest(unittest.TestCase):
    def test_basic(self):
        d = debugger("binaries/basic_test")
        d.run()
        bp = d.breakpoint("register_test")
        d.cont()
        self.assertTrue(bp.address == d.eip)
        d.cont()
        d.kill()

    def test_registers(self):
        d = debugger("binaries/basic_test")

        d.run()

        bp1 = d.breakpoint(0x8049185)
        bp2 = d.breakpoint(0x80491A2)
        bp3 = d.breakpoint(0x80491C6)
        bp4 = d.breakpoint(0x80491CF)

        d.cont()
        self.assertTrue(bp1.address == d.eip)

        self.assertTrue(d.al == 0x11)
        self.assertTrue(d.bl == 0x22)
        self.assertTrue(d.cl == 0x33)
        self.assertTrue(d.dl == 0x44)

        d.cont()
        self.assertTrue(bp2.address == d.eip)

        self.assertTrue(d.ax == 0x1122)
        self.assertTrue(d.bx == 0x2233)
        self.assertTrue(d.cx == 0x3344)
        self.assertTrue(d.dx == 0x4455)
        self.assertTrue(d.si == 0x5566)
        self.assertTrue(d.di == 0x6677)
        self.assertTrue(d.bp == 0x7788)

        d.cont()
        self.assertTrue(bp3.address == d.eip)

        self.assertTrue(d.eax == 0x11223344)
        self.assertTrue(d.ebx == 0x22334455)
        self.assertTrue(d.ecx == 0x33445566)
        self.assertTrue(d.edx == 0x44556677)
        self.assertTrue(d.esi == 0x55667788)
        self.assertTrue(d.edi == 0x66778899)
        self.assertTrue(d.ebp == 0x778899AA)

        d.cont()
        self.assertTrue(bp4.address == d.eip)

        self.assertTrue(d.ah == 0x11)
        self.assertTrue(d.bh == 0x22)
        self.assertTrue(d.ch == 0x33)
        self.assertTrue(d.dh == 0x44)

        self.assertIsInstance(d.threads[0], ThreadContextI386)

        d.cont()
        d.kill()

    def test_step(self):
        d = debugger("binaries/basic_test")

        d.run()
        bp = d.breakpoint("register_test")
        d.cont()

        self.assertTrue(bp.address == d.eip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 1 == d.eip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 3 == d.eip)
        self.assertTrue(bp.hit_count == 1)

        self.assertIsInstance(d.threads[0], ThreadContextI386)

        d.cont()
        d.kill()

    def test_step_hardware(self):
        d = debugger("binaries/basic_test")

        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()

        self.assertTrue(bp.address == d.eip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 1 == d.eip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 3 == d.eip)
        self.assertTrue(bp.hit_count == 1)

        self.assertIsInstance(d.threads[0], ThreadContextI386)

        d.cont()
        d.kill()


if __name__ == "__main__":
    unittest.main()
