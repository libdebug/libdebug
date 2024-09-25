#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BasicTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test")

    def test_basic(self):
        self.d.run()
        bp = self.d.breakpoint("register_test")
        self.d.cont()
        self.assertTrue(bp.address == self.d.regs.rip)
        self.d.cont()
        self.d.kill()

    def test_registers(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint(0x4011CA)
        bp2 = d.breakpoint(0x40128D)
        bp3 = d.breakpoint(0x401239)
        bp4 = d.breakpoint(0x4011F4)
        bp5 = d.breakpoint(0x401296)

        d.cont()
        self.assertTrue(bp1.address == d.regs.rip)

        self.assertTrue(d.regs.rax == 0x0011223344556677)
        self.assertTrue(d.regs.rbx == 0x1122334455667700)
        self.assertTrue(d.regs.rcx == 0x2233445566770011)
        self.assertTrue(d.regs.rdx == 0x3344556677001122)
        self.assertTrue(d.regs.rsi == 0x4455667700112233)
        self.assertTrue(d.regs.rdi == 0x5566770011223344)
        self.assertTrue(d.regs.rbp == 0x6677001122334455)
        self.assertTrue(d.regs.r8 == 0xAABBCCDD11223344)
        self.assertTrue(d.regs.r9 == 0xBBCCDD11223344AA)
        self.assertTrue(d.regs.r10 == 0xCCDD11223344AABB)
        self.assertTrue(d.regs.r11 == 0xDD11223344AABBCC)
        self.assertTrue(d.regs.r12 == 0x11223344AABBCCDD)
        self.assertTrue(d.regs.r13 == 0x223344AABBCCDD11)
        self.assertTrue(d.regs.r14 == 0x3344AABBCCDD1122)
        self.assertTrue(d.regs.r15 == 0x44AABBCCDD112233)

        d.cont()
        self.assertTrue(bp4.address == d.regs.rip)

        self.assertTrue(d.regs.al == 0x11)
        self.assertTrue(d.regs.bl == 0x22)
        self.assertTrue(d.regs.cl == 0x33)
        self.assertTrue(d.regs.dl == 0x44)
        self.assertTrue(d.regs.sil == 0x55)
        self.assertTrue(d.regs.dil == 0x66)
        self.assertTrue(d.regs.bpl == 0x77)
        self.assertTrue(d.regs.r8b == 0x88)
        self.assertTrue(d.regs.r9b == 0x99)
        self.assertTrue(d.regs.r10b == 0xAA)
        self.assertTrue(d.regs.r11b == 0xBB)
        self.assertTrue(d.regs.r12b == 0xCC)
        self.assertTrue(d.regs.r13b == 0xDD)
        self.assertTrue(d.regs.r14b == 0xEE)
        self.assertTrue(d.regs.r15b == 0xFF)

        d.cont()
        self.assertTrue(bp3.address == d.regs.rip)

        self.assertTrue(d.regs.ax == 0x1122)
        self.assertTrue(d.regs.bx == 0x2233)
        self.assertTrue(d.regs.cx == 0x3344)
        self.assertTrue(d.regs.dx == 0x4455)
        self.assertTrue(d.regs.si == 0x5566)
        self.assertTrue(d.regs.di == 0x6677)
        self.assertTrue(d.regs.bp == 0x7788)
        self.assertTrue(d.regs.r8w == 0x8899)
        self.assertTrue(d.regs.r9w == 0x99AA)
        self.assertTrue(d.regs.r10w == 0xAABB)
        self.assertTrue(d.regs.r11w == 0xBBCC)
        self.assertTrue(d.regs.r12w == 0xCCDD)
        self.assertTrue(d.regs.r13w == 0xDDEE)
        self.assertTrue(d.regs.r14w == 0xEEFF)
        self.assertTrue(d.regs.r15w == 0xFF00)

        d.cont()
        self.assertTrue(bp2.address == d.regs.rip)

        self.assertTrue(d.regs.eax == 0x11223344)
        self.assertTrue(d.regs.ebx == 0x22334455)
        self.assertTrue(d.regs.ecx == 0x33445566)
        self.assertTrue(d.regs.edx == 0x44556677)
        self.assertTrue(d.regs.esi == 0x55667788)
        self.assertTrue(d.regs.edi == 0x66778899)
        self.assertTrue(d.regs.ebp == 0x778899AA)
        self.assertTrue(d.regs.r8d == 0x8899AABB)
        self.assertTrue(d.regs.r9d == 0x99AABBCC)
        self.assertTrue(d.regs.r10d == 0xAABBCCDD)
        self.assertTrue(d.regs.r11d == 0xBBCCDD11)
        self.assertTrue(d.regs.r12d == 0xCCDD1122)
        self.assertTrue(d.regs.r13d == 0xDD112233)
        self.assertTrue(d.regs.r14d == 0x11223344)
        self.assertTrue(d.regs.r15d == 0x22334455)

        d.cont()
        self.assertTrue(bp5.address == d.regs.rip)

        self.assertTrue(d.regs.ah == 0x11)
        self.assertTrue(d.regs.bh == 0x22)
        self.assertTrue(d.regs.ch == 0x33)
        self.assertTrue(d.regs.dh == 0x44)

        self.d.cont()
        self.d.kill()

    def test_step(self):
        d = self.d

        d.run()
        bp = d.breakpoint("register_test")
        d.cont()

        self.assertTrue(bp.address == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 1 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 4 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.cont()
        d.kill()

    def test_step_hardware(self):
        d = self.d

        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()

        self.assertTrue(bp.address == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 1 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + 4 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.cont()
        d.kill()
        
    def test_register_find(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint(0x4011CA)
        bp2 = d.breakpoint(0x40128D)
        bp3 = d.breakpoint(0x401239)
        bp4 = d.breakpoint(0x4011F4)
        bp5 = d.breakpoint(0x401296)

        d.cont()
        self.assertTrue(bp1.address == d.regs.rip)
        
        self.assertIn("rax", d.regs.filter(0x0011223344556677))
        self.assertIn("rbx", d.regs.filter(0x1122334455667700))
        self.assertIn("rcx", d.regs.filter(0x2233445566770011))
        self.assertIn("rdx", d.regs.filter(0x3344556677001122))
        self.assertIn("rsi", d.regs.filter(0x4455667700112233))
        self.assertIn("rdi", d.regs.filter(0x5566770011223344))
        self.assertIn("rbp", d.regs.filter(0x6677001122334455))
        self.assertIn("r8", d.regs.filter(0xAABBCCDD11223344))
        self.assertIn("r9", d.regs.filter(0xBBCCDD11223344AA))
        self.assertIn("r10", d.regs.filter(0xCCDD11223344AABB))
        self.assertIn("r11", d.regs.filter(0xDD11223344AABBCC))
        self.assertIn("r12", d.regs.filter(0x11223344AABBCCDD))
        self.assertIn("r13", d.regs.filter(0x223344AABBCCDD11))
        self.assertIn("r14", d.regs.filter(0x3344AABBCCDD1122))
        self.assertIn("r15", d.regs.filter(0x44AABBCCDD112233))
        
        d.cont()
        self.assertTrue(bp4.address == d.regs.rip)
        
        self.assertIn("al", d.regs.filter(0x11))
        self.assertIn("bl", d.regs.filter(0x22))
        self.assertIn("cl", d.regs.filter(0x33))
        self.assertIn("dl", d.regs.filter(0x44))
        self.assertIn("sil", d.regs.filter(0x55))
        self.assertIn("dil", d.regs.filter(0x66))
        self.assertIn("bpl", d.regs.filter(0x77))
        self.assertIn("r8b", d.regs.filter(0x88))
        self.assertIn("r9b", d.regs.filter(0x99))
        self.assertIn("r10b", d.regs.filter(0xAA))
        self.assertIn("r11b", d.regs.filter(0xBB))
        self.assertIn("r12b", d.regs.filter(0xCC))
        self.assertIn("r13b", d.regs.filter(0xDD))
        self.assertIn("r14b", d.regs.filter(0xEE))
        self.assertIn("r15b", d.regs.filter(0xFF))

        d.cont()
        self.assertTrue(bp3.address == d.regs.rip)
        
        self.assertIn("ax", d.regs.filter(0x1122))
        self.assertIn("bx", d.regs.filter(0x2233))
        self.assertIn("cx", d.regs.filter(0x3344))
        self.assertIn("dx", d.regs.filter(0x4455))
        self.assertIn("si", d.regs.filter(0x5566))
        self.assertIn("di", d.regs.filter(0x6677))
        self.assertIn("bp", d.regs.filter(0x7788))
        self.assertIn("r8w", d.regs.filter(0x8899))
        self.assertIn("r9w", d.regs.filter(0x99AA))
        self.assertIn("r10w", d.regs.filter(0xAABB))
        self.assertIn("r11w", d.regs.filter(0xBBCC))
        self.assertIn("r12w", d.regs.filter(0xCCDD))
        self.assertIn("r13w", d.regs.filter(0xDDEE))
        self.assertIn("r14w", d.regs.filter(0xEEFF))
        self.assertIn("r15w", d.regs.filter(0xFF00))

        d.cont()
        self.assertTrue(bp2.address == d.regs.rip)
        
        self.assertIn("eax", d.regs.filter(0x11223344))
        self.assertIn("ebx", d.regs.filter(0x22334455))
        self.assertIn("ecx", d.regs.filter(0x33445566))
        self.assertIn("edx", d.regs.filter(0x44556677))
        self.assertIn("esi", d.regs.filter(0x55667788))
        self.assertIn("edi", d.regs.filter(0x66778899))
        self.assertIn("ebp", d.regs.filter(0x778899AA))
        self.assertIn("r8d", d.regs.filter(0x8899AABB))
        self.assertIn("r9d", d.regs.filter(0x99AABBCC))
        self.assertIn("r10d", d.regs.filter(0xAABBCCDD))
        self.assertIn("r11d", d.regs.filter(0xBBCCDD11))
        self.assertIn("r12d", d.regs.filter(0xCCDD1122))
        self.assertIn("r13d", d.regs.filter(0xDD112233))
        self.assertIn("r14d", d.regs.filter(0x11223344))
        self.assertIn("r15d", d.regs.filter(0x22334455))
        

        d.cont()
        self.assertTrue(bp5.address == d.regs.rip)
        
        self.assertIn("ah", d.regs.filter(0x11))
        self.assertIn("bh", d.regs.filter(0x22))
        self.assertIn("ch", d.regs.filter(0x33))
        self.assertIn("dh", d.regs.filter(0x44))
        

        self.d.cont()
        self.d.kill()


class BasicPieTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test_pie")

    def test_basic(self):
        d = self.d

        d.run()
        bp = d.breakpoint("register_test")
        d.cont()

        self.assertTrue(bp.address == d.regs.rip)
        self.assertTrue(d.regs.rdi == 0xAABBCCDD11223344)

        self.d.kill()


class HwBasicTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test")

    def test_basic(self):
        d = self.d
        d.run()
        bp = d.breakpoint(0x4011D1, hardware=True)
        self.d.cont()
        self.assertTrue(bp.address == d.regs.rip)
        self.d.kill()

    def test_registers(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint(0x4011CA, hardware=True)
        bp2 = d.breakpoint(0x40128D, hardware=False)
        bp3 = d.breakpoint(0x401239, hardware=True)
        bp4 = d.breakpoint(0x4011F4, hardware=False)
        bp5 = d.breakpoint(0x401296, hardware=True)

        d.cont()
        self.assertTrue(bp1.address == d.regs.rip)

        self.assertTrue(d.regs.rax == 0x0011223344556677)
        self.assertTrue(d.regs.rbx == 0x1122334455667700)
        self.assertTrue(d.regs.rcx == 0x2233445566770011)
        self.assertTrue(d.regs.rdx == 0x3344556677001122)
        self.assertTrue(d.regs.rsi == 0x4455667700112233)
        self.assertTrue(d.regs.rdi == 0x5566770011223344)
        self.assertTrue(d.regs.rbp == 0x6677001122334455)
        self.assertTrue(d.regs.r8 == 0xAABBCCDD11223344)
        self.assertTrue(d.regs.r9 == 0xBBCCDD11223344AA)
        self.assertTrue(d.regs.r10 == 0xCCDD11223344AABB)
        self.assertTrue(d.regs.r11 == 0xDD11223344AABBCC)
        self.assertTrue(d.regs.r12 == 0x11223344AABBCCDD)
        self.assertTrue(d.regs.r13 == 0x223344AABBCCDD11)
        self.assertTrue(d.regs.r14 == 0x3344AABBCCDD1122)
        self.assertTrue(d.regs.r15 == 0x44AABBCCDD112233)

        d.cont()
        self.assertTrue(bp4.address == d.regs.rip)

        self.assertTrue(d.regs.al == 0x11)
        self.assertTrue(d.regs.bl == 0x22)
        self.assertTrue(d.regs.cl == 0x33)
        self.assertTrue(d.regs.dl == 0x44)
        self.assertTrue(d.regs.sil == 0x55)
        self.assertTrue(d.regs.dil == 0x66)
        self.assertTrue(d.regs.bpl == 0x77)
        self.assertTrue(d.regs.r8b == 0x88)
        self.assertTrue(d.regs.r9b == 0x99)
        self.assertTrue(d.regs.r10b == 0xAA)
        self.assertTrue(d.regs.r11b == 0xBB)
        self.assertTrue(d.regs.r12b == 0xCC)
        self.assertTrue(d.regs.r13b == 0xDD)
        self.assertTrue(d.regs.r14b == 0xEE)
        self.assertTrue(d.regs.r15b == 0xFF)

        d.cont()
        self.assertTrue(bp3.address == d.regs.rip)

        self.assertTrue(d.regs.ax == 0x1122)
        self.assertTrue(d.regs.bx == 0x2233)
        self.assertTrue(d.regs.cx == 0x3344)
        self.assertTrue(d.regs.dx == 0x4455)
        self.assertTrue(d.regs.si == 0x5566)
        self.assertTrue(d.regs.di == 0x6677)
        self.assertTrue(d.regs.bp == 0x7788)
        self.assertTrue(d.regs.r8w == 0x8899)
        self.assertTrue(d.regs.r9w == 0x99AA)
        self.assertTrue(d.regs.r10w == 0xAABB)
        self.assertTrue(d.regs.r11w == 0xBBCC)
        self.assertTrue(d.regs.r12w == 0xCCDD)
        self.assertTrue(d.regs.r13w == 0xDDEE)
        self.assertTrue(d.regs.r14w == 0xEEFF)
        self.assertTrue(d.regs.r15w == 0xFF00)

        d.cont()
        self.assertTrue(bp2.address == d.regs.rip)

        self.assertTrue(d.regs.eax == 0x11223344)
        self.assertTrue(d.regs.ebx == 0x22334455)
        self.assertTrue(d.regs.ecx == 0x33445566)
        self.assertTrue(d.regs.edx == 0x44556677)
        self.assertTrue(d.regs.esi == 0x55667788)
        self.assertTrue(d.regs.edi == 0x66778899)
        self.assertTrue(d.regs.ebp == 0x778899AA)
        self.assertTrue(d.regs.r8d == 0x8899AABB)
        self.assertTrue(d.regs.r9d == 0x99AABBCC)
        self.assertTrue(d.regs.r10d == 0xAABBCCDD)
        self.assertTrue(d.regs.r11d == 0xBBCCDD11)
        self.assertTrue(d.regs.r12d == 0xCCDD1122)
        self.assertTrue(d.regs.r13d == 0xDD112233)
        self.assertTrue(d.regs.r14d == 0x11223344)
        self.assertTrue(d.regs.r15d == 0x22334455)

        d.cont()
        self.assertTrue(bp5.address == d.regs.rip)

        self.assertTrue(d.regs.ah == 0x11)
        self.assertTrue(d.regs.bh == 0x22)
        self.assertTrue(d.regs.ch == 0x33)
        self.assertTrue(d.regs.dh == 0x44)

        self.d.cont()
        self.d.kill()


class ControlFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        pass

    def test_step_until_1(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint("main")
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(0x40119D)

        self.assertTrue(d.regs.rip == 0x40119D)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()

    def test_step_until_2(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint(0x401148, hardware=True)
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(0x40119D, max_steps=7)

        self.assertTrue(d.regs.rip == 0x40115E)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()

    def test_step_until_3(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp = d.breakpoint(0x401148)

        # Let's put some breakpoints in-between
        d.breakpoint(0x40114F)
        d.breakpoint(0x401156)
        d.breakpoint(0x401162, hardware=True)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        # trace is [0x401148, 0x40114f, 0x401156, 0x401162, 0x401166, 0x401158, 0x40115b, 0x40115e]
        d.step_until(0x40119D, max_steps=7)

        self.assertTrue(d.regs.rip == 0x40115E)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()

    def test_step_and_cont(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.rip == 0x401180)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.rip == 0x401183)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()

    def test_step_and_cont_hardware(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.rip == 0x401180)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.regs.rip == 0x401183)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()

    def test_step_until_and_cont(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(0x401180)
        self.assertTrue(d.regs.rip == 0x401180)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()

    def test_step_until_and_cont_hardware(self):
        d = debugger("./binaries/breakpoint_test")
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(0x401180)
        self.assertTrue(d.regs.rip == 0x401180)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()


if __name__ == "__main__":
    unittest.main()
