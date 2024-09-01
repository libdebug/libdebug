#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext

class RegisterTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_registers_amd64(self):
        d = debugger(RESOLVE_EXE("basic_test"))

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

        d.cont()
        d.kill()
        d.terminate()

    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_registers_hardware_amd64(self):
        d = debugger(RESOLVE_EXE("basic_test"))

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

        d.cont()
        d.kill()
        d.terminate()
