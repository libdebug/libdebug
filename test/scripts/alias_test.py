#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class AliasTest(unittest.TestCase):
    def test_basic_alias(self):
        d = debugger("binaries/basic_test")
        d.r()
        bp = d.bp("register_test")
        d.c()
        self.assertTrue(bp.address == d.regs.rip)
        d.c()
        d.kill()

    def test_step_alias(self):
        d = debugger("binaries/basic_test")

        d.r()
        bp = d.bp("register_test")
        d.c()

        self.assertTrue(bp.address == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.si()

        self.assertTrue(bp.address + 1 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.si()

        self.assertTrue(bp.address + 4 == d.regs.rip)
        self.assertTrue(bp.hit_count == 1)

        d.c()
        d.kill()

    def test_step_until_alias(self):
        d = debugger("./binaries/breakpoint_test")
        d.r()

        bp1 = d.bp("main")
        bp2 = d.bp("random_function")
        d.c()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.su(0x401180)
        self.assertTrue(d.regs.rip == 0x401180)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.c()

        self.assertTrue(bp2.hit_on(d))

        d.c()

        d.kill()

    def test_memory_alias(self):
        d = debugger("binaries/memory_test")

        d.r()

        bp = d.bp("change_memory")

        d.c()

        assert d.regs.rip == bp.address

        address = d.regs.rdi
        prev = bytes(range(256))

        self.assertTrue(d.mem[address, 256] == prev)

        d.mem[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.mem[address : address + 256] == prev)

        d.kill()

    def test_finish_alias(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.r()
        d.bp(0x4011E3)
        d.c()

        self.assertEqual(d.regs.rip, 0x4011E3)

        # Finish function c
        d.fin(heuristic="step-mode")

        self.assertEqual(d.regs.rip, 0x401202)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.r()
        d.bp(0x401146)
        d.c()

        self.assertEqual(d.regs.rip, 0x401146)

        # Finish function a
        d.fin(heuristic="step-mode")

        self.assertEqual(d.regs.rip, 0x4011E0)

        d.kill()

    def test_waiting_alias(self):
        d = debugger("binaries/breakpoint_test", auto_interrupt_on_command=True)

        d.r()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.c()

        while True:
            d.w()
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

            d.c()

        d.kill()

    def test_interrupt_alias(self):
        d = debugger("binaries/basic_test")

        d.r()

        d.c()

        d.int()
        d.kill()
