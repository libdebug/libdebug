#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        TEST_STEP_ALIAS_OFFSET_1 = 1
        TEST_STEP_ALIAS_OFFSET_2 = 4

        TEST_STEP_UNTIL_1_ADDRESS = 0x40119D

        TEST_STEP_UNTIL_2_ADDRESS_1 = 0x401148
        TEST_STEP_UNTIL_2_ADDRESS_2 = 0x40119D
        TEST_STEP_UNTIL_2_ADDRESS_3 = 0x40115E

        TEST_STEP_UNTIL_3_ADDRESS_1 = 0x401148
        TEST_STEP_UNTIL_3_BP_1 = 0x40114F
        TEST_STEP_UNTIL_3_BP_2 = 0x401156
        TEST_STEP_UNTIL_3_BP_3 = 0x401162
        TEST_STEP_UNTIL_3_ADDRESS_2 = 0x40119D
        TEST_STEP_UNTIL_3_ADDRESS_3 = 0x40115E

        TEST_STEP_AND_CONT_ADDRESS_1 = 0x401180
        TEST_STEP_AND_CONT_ADDRESS_2 = 0x401183

        TEST_STEP_UNTIL_AND_CONT_ADDRESS = 0x401180
    case "aarch64":
        TEST_STEP_ALIAS_OFFSET_1 = 4
        TEST_STEP_ALIAS_OFFSET_2 = 8

        TEST_STEP_UNTIL_1_ADDRESS = BASE + 0x854

        TEST_STEP_UNTIL_2_ADDRESS_1 = 0x7fc
        TEST_STEP_UNTIL_2_ADDRESS_2 = BASE + 0x854
        TEST_STEP_UNTIL_2_ADDRESS_3 = BASE + 0x818

        TEST_STEP_UNTIL_3_ADDRESS_1 = 0x7fc
        TEST_STEP_UNTIL_3_BP_1 = 0x804
        TEST_STEP_UNTIL_3_BP_2 = 0x80c
        TEST_STEP_UNTIL_3_BP_3 = 0x808
        TEST_STEP_UNTIL_3_ADDRESS_2 = BASE + 0x854
        TEST_STEP_UNTIL_3_ADDRESS_3 = BASE + 0x818

        TEST_STEP_AND_CONT_ADDRESS_1 = BASE + 0x83c
        TEST_STEP_AND_CONT_ADDRESS_2 = BASE + 0x840

        TEST_STEP_UNTIL_AND_CONT_ADDRESS = BASE + 0x83c
    case "i386":
        TEST_STEP_ALIAS_OFFSET_1 = 1
        TEST_STEP_ALIAS_OFFSET_2 = 3

        TEST_STEP_UNTIL_1_ADDRESS = 0x401238

        TEST_STEP_UNTIL_2_ADDRESS_1 = 0x4011bd
        TEST_STEP_UNTIL_2_ADDRESS_2 = 0x401238
        TEST_STEP_UNTIL_2_ADDRESS_3 = 0x4011d3

        TEST_STEP_UNTIL_3_ADDRESS_1 = 0x4011bd
        TEST_STEP_UNTIL_3_BP_1 = 0x4011c4
        TEST_STEP_UNTIL_3_BP_2 = 0x4011cb
        TEST_STEP_UNTIL_3_BP_3 = 0x4011d7
        TEST_STEP_UNTIL_3_ADDRESS_2 = 0x401238
        TEST_STEP_UNTIL_3_ADDRESS_3 = 0x4011d3

        TEST_STEP_AND_CONT_ADDRESS_1 = 0x4011fc
        TEST_STEP_AND_CONT_ADDRESS_2 = 0x4011ff

        TEST_STEP_UNTIL_AND_CONT_ADDRESS = 0x4011fc
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class ControlFlowTest(TestCase):
    def test_basic(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        d.run()
        bp = d.breakpoint("register_test")
        d.cont()
        self.assertTrue(bp.address == d.instruction_pointer)
        d.cont()
        d.kill()
        d.terminate()

    def test_basic_hardware(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()
        self.assertTrue(bp.address == d.instruction_pointer)
        d.kill()
        d.terminate()

    def test_basic_pie(self):
        d = debugger(RESOLVE_EXE("basic_test_pie"))
        d.run()
        bp = d.breakpoint("register_test")
        d.cont()
        self.assertTrue(bp.address == d.instruction_pointer)
        d.kill()
        d.terminate()

    def test_step(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()
        bp = d.breakpoint("register_test")
        d.cont()

        self.assertTrue(bp.address == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_1 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_2 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.cont()
        d.kill()
        d.terminate()

    def test_step_hardware(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()

        self.assertTrue(bp.address == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_1 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.step()

        self.assertTrue(bp.address + TEST_STEP_ALIAS_OFFSET_2 == d.instruction_pointer)
        self.assertTrue(bp.hit_count == 1)

        d.cont()
        d.kill()
        d.terminate()

    def test_step_until_1(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp = d.breakpoint("main")
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(TEST_STEP_UNTIL_1_ADDRESS)

        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_1_ADDRESS)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_until_2(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp = d.breakpoint(TEST_STEP_UNTIL_2_ADDRESS_1, hardware=True)
        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.step_until(TEST_STEP_UNTIL_2_ADDRESS_2, max_steps=7)

        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_2_ADDRESS_3)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_until_3(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp = d.breakpoint(TEST_STEP_UNTIL_3_ADDRESS_1)

        # Let's put some breakpoints in-between
        d.breakpoint(TEST_STEP_UNTIL_3_BP_1)
        d.breakpoint(TEST_STEP_UNTIL_3_BP_2)
        d.breakpoint(TEST_STEP_UNTIL_3_BP_3, hardware=True)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        # trace is [0x401148, 0x40114f, 0x401156, 0x401162, 0x401166, 0x401158, 0x40115b, 0x40115e]
        d.step_until(TEST_STEP_UNTIL_3_ADDRESS_2, max_steps=7)

        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_3_ADDRESS_3)
        self.assertTrue(bp.hit_count == 1)
        self.assertFalse(bp.hit_on(d))

        d.kill()
        d.terminate()

    def test_step_and_cont(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.instruction_pointer == TEST_STEP_AND_CONT_ADDRESS_1)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.instruction_pointer == TEST_STEP_AND_CONT_ADDRESS_2)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_and_cont_hardware(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.instruction_pointer == TEST_STEP_AND_CONT_ADDRESS_1)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step()
        self.assertTrue(d.instruction_pointer == TEST_STEP_AND_CONT_ADDRESS_2)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_until_and_cont(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp1 = d.breakpoint("main")
        bp2 = d.breakpoint("random_function")
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(TEST_STEP_UNTIL_AND_CONT_ADDRESS)
        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_AND_CONT_ADDRESS)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()

    def test_step_until_and_cont_hardware(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        bp1 = d.breakpoint("main", hardware=True)
        bp2 = d.breakpoint("random_function", hardware=True)
        d.cont()

        self.assertTrue(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.step_until(TEST_STEP_UNTIL_AND_CONT_ADDRESS)
        self.assertTrue(d.instruction_pointer == TEST_STEP_UNTIL_AND_CONT_ADDRESS)
        self.assertFalse(bp1.hit_on(d))
        self.assertFalse(bp2.hit_on(d))

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        d.cont()

        d.kill()
        d.terminate()
