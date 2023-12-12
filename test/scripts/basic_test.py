#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini, Gabriele Digregorio.
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


class BasicTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test")
        self.exceptions = []

    def test_basic(self):
        def bp(d, breakpoint):
            try:
                self.assertTrue(breakpoint.address == d.rip)
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b(0x4011DB, bp)
        self.d.cont()
        self.d.kill()

        if self.exceptions:
            raise self.exceptions[0]

        
    def test_registers(self):
        global hit_bp
        hit_bp = 0

        def bp_64(d, _):
            try:
                global hit_bp

                self.assertTrue(d.rax == 0x0011223344556677)
                self.assertTrue(d.rbx == 0x1122334455667700)
                self.assertTrue(d.rcx == 0x2233445566770011)
                self.assertTrue(d.rdx == 0x3344556677001122)
                self.assertTrue(d.rsi == 0x4455667700112233)
                self.assertTrue(d.rdi == 0x5566770011223344)
                self.assertTrue(d.rbp == 0x6677001122334455)
                self.assertTrue(d.r8 == 0xAABBCCDD11223344)
                self.assertTrue(d.r9 == 0xBBCCDD11223344AA)
                self.assertTrue(d.r10 == 0xCCDD11223344AABB)
                self.assertTrue(d.r11 == 0xDD11223344AABBCC)
                self.assertTrue(d.r12 == 0x11223344AABBCCDD)
                self.assertTrue(d.r13 == 0x223344AABBCCDD11)
                self.assertTrue(d.r14 == 0x3344AABBCCDD1122)
                self.assertTrue(d.r15 == 0x44AABBCCDD112233)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_32(d, _):
            try:
                global hit_bp

                self.assertTrue(d.eax == 0x11223344)
                self.assertTrue(d.ebx == 0x22334455)
                self.assertTrue(d.ecx == 0x33445566)
                self.assertTrue(d.edx == 0x44556677)
                self.assertTrue(d.esi == 0x55667788)
                self.assertTrue(d.edi == 0x66778899)
                self.assertTrue(d.ebp == 0x778899AA)
                self.assertTrue(d.r8d == 0x8899AABB)
                self.assertTrue(d.r9d == 0x99AABBCC)
                self.assertTrue(d.r10d == 0xAABBCCDD)
                self.assertTrue(d.r11d == 0xBBCCDD11)
                self.assertTrue(d.r12d == 0xCCDD1122)
                self.assertTrue(d.r13d == 0xDD112233)
                self.assertTrue(d.r14d == 0x11223344)
                self.assertTrue(d.r15d == 0x22334455)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_16(d, _):
            try:
                global hit_bp

                self.assertTrue(d.ax == 0x1122)
                self.assertTrue(d.bx == 0x2233)
                self.assertTrue(d.cx == 0x3344)
                self.assertTrue(d.dx == 0x4455)
                self.assertTrue(d.si == 0x5566)
                self.assertTrue(d.di == 0x6677)
                self.assertTrue(d.bp == 0x7788)
                self.assertTrue(d.r8w == 0x8899)
                self.assertTrue(d.r9w == 0x99AA)
                self.assertTrue(d.r10w == 0xAABB)
                self.assertTrue(d.r11w == 0xBBCC)
                self.assertTrue(d.r12w == 0xCCDD)
                self.assertTrue(d.r13w == 0xDDEE)
                self.assertTrue(d.r14w == 0xEEFF)
                self.assertTrue(d.r15w == 0xFF00)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_8l(d, _):
            try:
                global hit_bp

                self.assertTrue(d.al == 0x11)
                self.assertTrue(d.bl == 0x22)
                self.assertTrue(d.cl == 0x33)
                self.assertTrue(d.dl == 0x44)
                self.assertTrue(d.sil == 0x55)
                self.assertTrue(d.dil == 0x66)
                self.assertTrue(d.bpl == 0x77)
                self.assertTrue(d.r8b == 0x88)
                self.assertTrue(d.r9b == 0x99)
                self.assertTrue(d.r10b == 0xAA)
                self.assertTrue(d.r11b == 0xBB)
                self.assertTrue(d.r12b == 0xCC)
                self.assertTrue(d.r13b == 0xDD)
                self.assertTrue(d.r14b == 0xEE)
                self.assertTrue(d.r15b == 0xFF)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_8h(d, _):
            try:
                global hit_bp

                self.assertTrue(d.ah == 0x11)
                self.assertTrue(d.bh == 0x22)
                self.assertTrue(d.ch == 0x33)
                self.assertTrue(d.dh == 0x44)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b(0x4011CA, bp_64)
        self.d.b(0x4011F4, bp_8l)
        self.d.b(0x401239, bp_16)
        self.d.b(0x40128D, bp_32)
        self.d.b(0x401296, bp_8h)
        self.d.cont()
        self.d.kill()
        self.assertTrue(hit_bp == 5)

        if self.exceptions:
            raise self.exceptions[0]


class BasicPieTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test_pie")
        self.exceptions = []

    def test_basic(self):
        global called
        called = False

        def bp(d, _):
            try:
                global called
                self.assertTrue(d.rdi == 0xAABBCCDD11223344)
                called = True
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b("register_test", bp)
        self.d.cont()
        self.d.kill()
        self.assertTrue(called)

        if self.exceptions:
            raise self.exceptions[0]


class HwBasicTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/basic_test")
        self.exceptions = []

    def test_basic(self):
        def bp(d, breakpoint):
            try:
                self.assertTrue(breakpoint.address == d.rip)
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b(0x4011DB, bp)
        self.d.cont()
        self.d.kill()
        self.assertTrue(True)

        if self.exceptions:
            raise self.exceptions[0]

    def test_registers(self):
        global hit_bp
        hit_bp = 0

        def bp_64(d, _):
            try:
                global hit_bp

                self.assertTrue(d.rax == 0x0011223344556677)
                self.assertTrue(d.rbx == 0x1122334455667700)
                self.assertTrue(d.rcx == 0x2233445566770011)
                self.assertTrue(d.rdx == 0x3344556677001122)
                self.assertTrue(d.rsi == 0x4455667700112233)
                self.assertTrue(d.rdi == 0x5566770011223344)
                self.assertTrue(d.rbp == 0x6677001122334455)
                self.assertTrue(d.r8 == 0xAABBCCDD11223344)
                self.assertTrue(d.r9 == 0xBBCCDD11223344AA)
                self.assertTrue(d.r10 == 0xCCDD11223344AABB)
                self.assertTrue(d.r11 == 0xDD11223344AABBCC)
                self.assertTrue(d.r12 == 0x11223344AABBCCDD)
                self.assertTrue(d.r13 == 0x223344AABBCCDD11)
                self.assertTrue(d.r14 == 0x3344AABBCCDD1122)
                self.assertTrue(d.r15 == 0x44AABBCCDD112233)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_32(d, _):
            try:
                global hit_bp

                self.assertTrue(d.eax == 0x11223344)
                self.assertTrue(d.ebx == 0x22334455)
                self.assertTrue(d.ecx == 0x33445566)
                self.assertTrue(d.edx == 0x44556677)
                self.assertTrue(d.esi == 0x55667788)
                self.assertTrue(d.edi == 0x66778899)
                self.assertTrue(d.ebp == 0x778899AA)
                self.assertTrue(d.r8d == 0x8899AABB)
                self.assertTrue(d.r9d == 0x99AABBCC)
                self.assertTrue(d.r10d == 0xAABBCCDD)
                self.assertTrue(d.r11d == 0xBBCCDD11)
                self.assertTrue(d.r12d == 0xCCDD1122)
                self.assertTrue(d.r13d == 0xDD112233)
                self.assertTrue(d.r14d == 0x11223344)
                self.assertTrue(d.r15d == 0x22334455)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_16(d, _):
            try:
                global hit_bp

                self.assertTrue(d.ax == 0x1122)
                self.assertTrue(d.bx == 0x2233)
                self.assertTrue(d.cx == 0x3344)
                self.assertTrue(d.dx == 0x4455)
                self.assertTrue(d.si == 0x5566)
                self.assertTrue(d.di == 0x6677)
                self.assertTrue(d.bp == 0x7788)
                self.assertTrue(d.r8w == 0x8899)
                self.assertTrue(d.r9w == 0x99AA)
                self.assertTrue(d.r10w == 0xAABB)
                self.assertTrue(d.r11w == 0xBBCC)
                self.assertTrue(d.r12w == 0xCCDD)
                self.assertTrue(d.r13w == 0xDDEE)
                self.assertTrue(d.r14w == 0xEEFF)
                self.assertTrue(d.r15w == 0xFF00)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_8l(d, _):
            try:
                global hit_bp

                self.assertTrue(d.al == 0x11)
                self.assertTrue(d.bl == 0x22)
                self.assertTrue(d.cl == 0x33)
                self.assertTrue(d.dl == 0x44)
                self.assertTrue(d.sil == 0x55)
                self.assertTrue(d.dil == 0x66)
                self.assertTrue(d.bpl == 0x77)
                self.assertTrue(d.r8b == 0x88)
                self.assertTrue(d.r9b == 0x99)
                self.assertTrue(d.r10b == 0xAA)
                self.assertTrue(d.r11b == 0xBB)
                self.assertTrue(d.r12b == 0xCC)
                self.assertTrue(d.r13b == 0xDD)
                self.assertTrue(d.r14b == 0xEE)
                self.assertTrue(d.r15b == 0xFF)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        def bp_8h(d, _):
            try:
                global hit_bp

                self.assertTrue(d.ah == 0x11)
                self.assertTrue(d.bh == 0x22)
                self.assertTrue(d.ch == 0x33)
                self.assertTrue(d.dh == 0x44)

                hit_bp += 1
            except Exception as e:
                self.exceptions.append(e)

        self.d.start()
        self.d.b(0x4011CA, bp_64, hardware_assisted=True)
        self.d.b(0x4011F4, bp_8l, hardware_assisted=True)
        self.d.b(0x401239, bp_16, hardware_assisted=False)
        self.d.b(0x40128D, bp_32, hardware_assisted=True)
        self.d.b(0x401296, bp_8h, hardware_assisted=True)
        self.d.cont()
        self.d.kill()

        self.assertTrue(hit_bp == 5)

        if self.exceptions:
            raise self.exceptions[0]

if __name__ == '__main__':
    unittest.main()