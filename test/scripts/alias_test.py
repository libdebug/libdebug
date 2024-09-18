#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipIf
from utils.thread_utils import FUN_ARG_0
from utils.binary_utils import BASE, PLATFORM, RESOLVE_EXE

from libdebug import debugger


match PLATFORM:
    case "amd64":
        TEST_STEP_ALIAS_OFFSET_1 = 1
        TEST_STEP_ALIAS_OFFSET_2 = 4

        TEST_STEP_UNTIL_ALIAS_ADDRESS = 0x401180

        TEST_FINISH_ALIAS_ADDRESS_1 = 0x4011E0
        TEST_FINISH_ALIAS_ADDRESS_2 = 0x401202
        TEST_FINISH_ALIAS_ADDRESS_3 = 0x4011E3
        TEST_FINISH_ALIAS_FUNCTION_A_ADDRESS = 0x401146

        TEST_WAITING_ALIAS_BP2_ADDRESS = 0x40115B
        TEST_WAITING_ALIAS_BP3_ADDRESS = 0x40116D

        def CHECK_REGISTERS(harness, d):
            harness.assertEqual(d.regs.rsi, 45)
            harness.assertEqual(d.regs.esi, 45)
            harness.assertEqual(d.regs.si, 45)
            harness.assertEqual(d.regs.sil, 45)
    case "aarch64":
        TEST_STEP_ALIAS_OFFSET_1 = 4
        TEST_STEP_ALIAS_OFFSET_2 = 8

        TEST_STEP_UNTIL_ALIAS_ADDRESS = BASE + 0x083c

        TEST_FINISH_ALIAS_ADDRESS_1 = BASE + 0x0908
        TEST_FINISH_ALIAS_ADDRESS_2 = BASE + 0x0938
        TEST_FINISH_ALIAS_ADDRESS_3 = BASE + 0x0914
        TEST_FINISH_ALIAS_FUNCTION_A_ADDRESS = BASE + 0x0814

        TEST_WAITING_ALIAS_BP2_ADDRESS = 0x7fc
        TEST_WAITING_ALIAS_BP3_ADDRESS = 0x820

        def CHECK_REGISTERS(harness, d):
            harness.assertEqual(d.regs.x1, 45)
            harness.assertEqual(d.regs.w1, 45)
    case "i386":
        TEST_STEP_ALIAS_OFFSET_1 = 1
        TEST_STEP_ALIAS_OFFSET_2 = 3

        TEST_STEP_UNTIL_ALIAS_ADDRESS = BASE + 0x11fc

        TEST_FINISH_ALIAS_ADDRESS_1 = BASE + 0x125f
        TEST_FINISH_ALIAS_ADDRESS_2 = BASE + 0x128f
        TEST_FINISH_ALIAS_ADDRESS_3 = BASE + 0x1262
        TEST_FINISH_ALIAS_FUNCTION_A_ADDRESS = BASE + 0x11a9

        TEST_WAITING_ALIAS_BP2_ADDRESS = 0x11d0
        TEST_WAITING_ALIAS_BP3_ADDRESS = 0x11ea

        def CHECK_REGISTERS(harness, d):
            value = int.from_bytes(d.memory[d.regs.esp + 4, 4], "little")
            harness.assertEqual(value, 45)
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class AliasTest(TestCase):
    def test_basic_alias(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        d.r()
        bp = d.bp("register_test")
        d.c()
        self.assertTrue(bp.address == d.instruction_pointer)
        d.c()
        d.kill()
        d.terminate()

    def test_step_alias(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.r()
        bp = d.bp("register_test")
        d.c()

        self.assertTrue(bp.address == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.si()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_1 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.si()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_2 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.c()
        d.kill()
        d.terminate()

    def test_step_until_alias(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.r()

        bp1 = d.bp("main")
        bp2 = d.bp("random_function")
        d.c()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.su(TEST_STEP_UNTIL_ALIAS_ADDRESS)
        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_ALIAS_ADDRESS)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.c()

        self.assertTrue(bp2.hit_on(d))

        d.c()

        d.kill()
        d.terminate()

    def test_memory_alias(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.r()

        bp = d.bp("change_memory")

        d.c()

        assert d.instruction_pointer == bp.address

        address = FUN_ARG_0(d)
        prev = bytes(range(256))

        self.assertTrue(d.mem[address, 256] == prev)

        d.mem[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.mem[address : address + 256] == prev)

        d.kill()
        d.terminate()

    @skipIf(PLATFORM == "i386", "Test not supported on i386")
    def test_finish_alias(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.r()
        d.bp(TEST_FINISH_ALIAS_ADDRESS_3)
        d.c()

        self.assertEqual(d.instruction_pointer, TEST_FINISH_ALIAS_ADDRESS_3)

        # Finish function c
        d.fin(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, TEST_FINISH_ALIAS_ADDRESS_2)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.r()
        d.bp(TEST_FINISH_ALIAS_FUNCTION_A_ADDRESS)
        d.c()

        self.assertEqual(d.instruction_pointer, TEST_FINISH_ALIAS_FUNCTION_A_ADDRESS)

        # Finish function a
        d.fin(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, TEST_FINISH_ALIAS_ADDRESS_1)

        d.kill()
        d.terminate()

    def test_waiting_alias(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"), auto_interrupt_on_command=True)

        d.r()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(TEST_WAITING_ALIAS_BP2_ADDRESS, file="binary")
        bp3 = d.breakpoint(TEST_WAITING_ALIAS_BP3_ADDRESS, file="binary")

        counter = 1

        d.c()

        while True:
            d.w()
            if d.instruction_pointer == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.instruction_pointer == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.instruction_pointer == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                CHECK_REGISTERS(self, d)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.c()

        d.kill()
        d.terminate()

    def test_interrupt_alias(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.r()

        d.c()

        d.int()
        d.kill()
        d.terminate()
