#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        BP2_ADDRESS = 0x40115B
        BP3_ADDRESS = 0x40116D
        RBP1_ADDRESS = 0x4011CA
        RBP2_ADDRESS = 0x40128D
        RBP3_ADDRESS = 0x401239
        RBP4_ADDRESS = 0x4011F4
        RBP5_ADDRESS = 0x401296

        def BP3_VALIDATE(harness, bpd):
            harness.assertTrue(bpd.regs.rsi == 45)
            harness.assertTrue(bpd.regs.esi == 45)
            harness.assertTrue(bpd.regs.si == 45)
            harness.assertTrue(bpd.regs.sil == 45)

        def RBP1_VALIDATE(harness, red):
            harness.assertTrue(red.regs.rax == 0x0011223344556677)
            harness.assertTrue(red.regs.rbx == 0x1122334455667700)
            harness.assertTrue(red.regs.rcx == 0x2233445566770011)
            harness.assertTrue(red.regs.rdx == 0x3344556677001122)
            harness.assertTrue(red.regs.rsi == 0x4455667700112233)
            harness.assertTrue(red.regs.rdi == 0x5566770011223344)
            harness.assertTrue(red.regs.rbp == 0x6677001122334455)
            harness.assertTrue(red.regs.r8 == 0xAABBCCDD11223344)
            harness.assertTrue(red.regs.r9 == 0xBBCCDD11223344AA)
            harness.assertTrue(red.regs.r10 == 0xCCDD11223344AABB)
            harness.assertTrue(red.regs.r11 == 0xDD11223344AABBCC)
            harness.assertTrue(red.regs.r12 == 0x11223344AABBCCDD)
            harness.assertTrue(red.regs.r13 == 0x223344AABBCCDD11)
            harness.assertTrue(red.regs.r14 == 0x3344AABBCCDD1122)
            harness.assertTrue(red.regs.r15 == 0x44AABBCCDD112233)

        def RBP4_VALIDATE(harness, red):
            harness.assertTrue(red.regs.al == 0x11)
            harness.assertTrue(red.regs.bl == 0x22)
            harness.assertTrue(red.regs.cl == 0x33)
            harness.assertTrue(red.regs.dl == 0x44)
            harness.assertTrue(red.regs.sil == 0x55)
            harness.assertTrue(red.regs.dil == 0x66)
            harness.assertTrue(red.regs.bpl == 0x77)
            harness.assertTrue(red.regs.r8b == 0x88)
            harness.assertTrue(red.regs.r9b == 0x99)
            harness.assertTrue(red.regs.r10b == 0xAA)
            harness.assertTrue(red.regs.r11b == 0xBB)
            harness.assertTrue(red.regs.r12b == 0xCC)
            harness.assertTrue(red.regs.r13b == 0xDD)
            harness.assertTrue(red.regs.r14b == 0xEE)
            harness.assertTrue(red.regs.r15b == 0xFF)

        def RBP3_VALIDATE(harness, red):
            harness.assertTrue(red.regs.ax == 0x1122)
            harness.assertTrue(red.regs.bx == 0x2233)
            harness.assertTrue(red.regs.cx == 0x3344)
            harness.assertTrue(red.regs.dx == 0x4455)
            harness.assertTrue(red.regs.si == 0x5566)
            harness.assertTrue(red.regs.di == 0x6677)
            harness.assertTrue(red.regs.bp == 0x7788)
            harness.assertTrue(red.regs.r8w == 0x8899)
            harness.assertTrue(red.regs.r9w == 0x99AA)
            harness.assertTrue(red.regs.r10w == 0xAABB)
            harness.assertTrue(red.regs.r11w == 0xBBCC)
            harness.assertTrue(red.regs.r12w == 0xCCDD)
            harness.assertTrue(red.regs.r13w == 0xDDEE)
            harness.assertTrue(red.regs.r14w == 0xEEFF)
            harness.assertTrue(red.regs.r15w == 0xFF00)

        def RBP2_VALIDATE(harness, red):
            harness.assertTrue(red.regs.eax == 0x11223344)
            harness.assertTrue(red.regs.ebx == 0x22334455)
            harness.assertTrue(red.regs.ecx == 0x33445566)
            harness.assertTrue(red.regs.edx == 0x44556677)
            harness.assertTrue(red.regs.esi == 0x55667788)
            harness.assertTrue(red.regs.edi == 0x66778899)
            harness.assertTrue(red.regs.ebp == 0x778899AA)
            harness.assertTrue(red.regs.r8d == 0x8899AABB)
            harness.assertTrue(red.regs.r9d == 0x99AABBCC)
            harness.assertTrue(red.regs.r10d == 0xAABBCCDD)
            harness.assertTrue(red.regs.r11d == 0xBBCCDD11)
            harness.assertTrue(red.regs.r12d == 0xCCDD1122)
            harness.assertTrue(red.regs.r13d == 0xDD112233)
            harness.assertTrue(red.regs.r14d == 0x11223344)
            harness.assertTrue(red.regs.r15d == 0x22334455)

        def RBP5_VALIDATE(harness, red):
            harness.assertTrue(red.regs.ah == 0x11)
            harness.assertTrue(red.regs.bh == 0x22)
            harness.assertTrue(red.regs.ch == 0x33)
            harness.assertTrue(red.regs.dh == 0x44)
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class MultipleDebuggersTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_multiple_debuggers_amd64(self):
        bpd = debugger(RESOLVE_EXE("breakpoint_test"))
        red = debugger(RESOLVE_EXE("basic_test"))

        bpd.run()
        red.run()

        bp1 = bpd.breakpoint("random_function")
        bp2 = bpd.breakpoint(BP2_ADDRESS)
        bp3 = bpd.breakpoint(BP3_ADDRESS)

        rbp1 = red.breakpoint(RBP1_ADDRESS, hardware=True)
        rbp2 = red.breakpoint(RBP2_ADDRESS, hardware=False)
        rbp3 = red.breakpoint(RBP3_ADDRESS, hardware=True)
        rbp4 = red.breakpoint(RBP4_ADDRESS, hardware=False)
        rbp5 = red.breakpoint(RBP5_ADDRESS, hardware=True)

        counter = 1

        bpd.cont()
        red.cont()
        disable_red = False

        while True:

            if bpd.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(bpd))
                self.assertFalse(bp2.hit_on(bpd))
                self.assertFalse(bp3.hit_on(bpd))
            elif bpd.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(bpd))
                self.assertFalse(bp1.hit_on(bpd))
                self.assertFalse(bp3.hit_on(bpd))
                counter += 1
            elif bpd.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                BP3_VALIDATE(self, bpd)
                self.assertTrue(bp3.hit_on(bpd))
                self.assertFalse(bp1.hit_on(bpd))
                self.assertFalse(bp2.hit_on(bpd))
                break

            if rbp1.hit_on(red):
                RBP1_VALIDATE(self, red)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 0)
                self.assertEqual(rbp4.hit_count, 0)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp4.hit_on(red):
                RBP4_VALIDATE(self, red)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 0)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp3.hit_on(red):
                RBP3_VALIDATE(self, red)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 0)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp2.hit_on(red):
                RBP2_VALIDATE(self, red)
                self.assertEqual(rbp1.hit_count, 1)
                self.assertEqual(rbp2.hit_count, 1)
                self.assertEqual(rbp3.hit_count, 1)
                self.assertEqual(rbp4.hit_count, 1)
                self.assertEqual(rbp5.hit_count, 0)
            elif rbp5.hit_on(red):
                RBP5_VALIDATE(self, red)
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
