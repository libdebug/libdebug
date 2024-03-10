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

from libdebug import debugger
import unittest


class MultipleDebuggersTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_multiple_debuggers(self):
        bpd = debugger("binaries/breakpoint_test")
        red = debugger("binaries/basic_test")

        bpd.run()
        red.run()

        bp1 = bpd.breakpoint("random_function")
        bp2 = bpd.breakpoint(0x40115B)
        bp3 = bpd.breakpoint(0x40116D)

        rbp1 = red.breakpoint(0x4011CA, hardware=True)
        rbp2 = red.breakpoint(0x40128D, hardware=False)
        rbp3 = red.breakpoint(0x401239, hardware=True)
        rbp4 = red.breakpoint(0x4011F4, hardware=False)
        rbp5 = red.breakpoint(0x401296, hardware=True)

        counter = 1

        bpd.cont()
        red.cont()
        disable_red = False

        while True:
            bpd.wait()

            if not disable_red:
                red.wait()

            if bpd.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(bpd))
                self.assertFalse(bp2.hit_on(bpd))
                self.assertFalse(bp3.hit_on(bpd))
            elif bpd.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(bpd))
                self.assertFalse(bp1.hit_on(bpd))
                self.assertFalse(bp3.hit_on(bpd))
                counter += 1
            elif bpd.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(bpd.rsi == 45)
                self.assertTrue(bpd.esi == 45)
                self.assertTrue(bpd.si == 45)
                self.assertTrue(bpd.sil == 45)
                self.assertTrue(bp3.hit_on(bpd))
                self.assertFalse(bp1.hit_on(bpd))
                self.assertFalse(bp2.hit_on(bpd))
                break

            if rbp1.hit_on(red):
                self.assertTrue(red.rax == 0x0011223344556677)
                self.assertTrue(red.rbx == 0x1122334455667700)
                self.assertTrue(red.rcx == 0x2233445566770011)
                self.assertTrue(red.rdx == 0x3344556677001122)
                self.assertTrue(red.rsi == 0x4455667700112233)
                self.assertTrue(red.rdi == 0x5566770011223344)
                self.assertTrue(red.rbp == 0x6677001122334455)
                self.assertTrue(red.r8 == 0xAABBCCDD11223344)
                self.assertTrue(red.r9 == 0xBBCCDD11223344AA)
                self.assertTrue(red.r10 == 0xCCDD11223344AABB)
                self.assertTrue(red.r11 == 0xDD11223344AABBCC)
                self.assertTrue(red.r12 == 0x11223344AABBCCDD)
                self.assertTrue(red.r13 == 0x223344AABBCCDD11)
                self.assertTrue(red.r14 == 0x3344AABBCCDD1122)
                self.assertTrue(red.r15 == 0x44AABBCCDD112233)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 0)
                self.assertEqual(rbp4.hit_count, 0)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp4.hit_on(red):
                self.assertTrue(red.al == 0x11)
                self.assertTrue(red.bl == 0x22)
                self.assertTrue(red.cl == 0x33)
                self.assertTrue(red.dl == 0x44)
                self.assertTrue(red.sil == 0x55)
                self.assertTrue(red.dil == 0x66)
                self.assertTrue(red.bpl == 0x77)
                self.assertTrue(red.r8b == 0x88)
                self.assertTrue(red.r9b == 0x99)
                self.assertTrue(red.r10b == 0xAA)
                self.assertTrue(red.r11b == 0xBB)
                self.assertTrue(red.r12b == 0xCC)
                self.assertTrue(red.r13b == 0xDD)
                self.assertTrue(red.r14b == 0xEE)
                self.assertTrue(red.r15b == 0xFF)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 0)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp3.hit_on(red):
                self.assertTrue(red.ax == 0x1122)
                self.assertTrue(red.bx == 0x2233)
                self.assertTrue(red.cx == 0x3344)
                self.assertTrue(red.dx == 0x4455)
                self.assertTrue(red.si == 0x5566)
                self.assertTrue(red.di == 0x6677)
                self.assertTrue(red.bp == 0x7788)
                self.assertTrue(red.r8w == 0x8899)
                self.assertTrue(red.r9w == 0x99AA)
                self.assertTrue(red.r10w == 0xAABB)
                self.assertTrue(red.r11w == 0xBBCC)
                self.assertTrue(red.r12w == 0xCCDD)
                self.assertTrue(red.r13w == 0xDDEE)
                self.assertTrue(red.r14w == 0xEEFF)
                self.assertTrue(red.r15w == 0xFF00)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp2.hit_on(red):
                self.assertTrue(red.eax == 0x11223344)
                self.assertTrue(red.ebx == 0x22334455)
                self.assertTrue(red.ecx == 0x33445566)
                self.assertTrue(red.edx == 0x44556677)
                self.assertTrue(red.esi == 0x55667788)
                self.assertTrue(red.edi == 0x66778899)
                self.assertTrue(red.ebp == 0x778899AA)
                self.assertTrue(red.r8d == 0x8899AABB)
                self.assertTrue(red.r9d == 0x99AABBCC)
                self.assertTrue(red.r10d == 0xAABBCCDD)
                self.assertTrue(red.r11d == 0xBBCCDD11)
                self.assertTrue(red.r12d == 0xCCDD1122)
                self.assertTrue(red.r13d == 0xDD112233)
                self.assertTrue(red.r14d == 0x11223344)
                self.assertTrue(red.r15d == 0x22334455)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 1)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp5.hit_on(red):
                self.assertTrue(red.ah == 0x11)
                self.assertTrue(red.bh == 0x22)
                self.assertTrue(red.ch == 0x33)
                self.assertTrue(red.dh == 0x44)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 1)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 1)
            else:
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 1)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 1)
                disable_red = True

            bpd.cont()
            if not disable_red:
                red.cont()

        bpd.kill()
        red.kill()

        bpd.terminate()
        red.terminate()
