#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        TEST_ENTRYPOINT = 0x4011f8

        # Addresses of the dummy functions
        CALL_C_ADDRESS = 0x4011fd
        TEST_BREAKPOINT_ADDRESS = 0x4011f1

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = 0x401202
    case "aarch64":
        TEST_ENTRYPOINT = BASE + 0x930

        # Addresses of the dummy functions
        CALL_C_ADDRESS = BASE + 0x934
        TEST_BREAKPOINT_ADDRESS = BASE + 0x920

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = BASE + 0x938
    case "i386":
        TEST_ENTRYPOINT = 0x401285

        # Addresses of the dummy functions
        CALL_C_ADDRESS = 0x40128a
        TEST_BREAKPOINT_ADDRESS = 0x401277

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = 0x40128f
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class NextTest(TestCase):
    def test_next(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.instruction_pointer, TEST_ENTRYPOINT)

        # -------- Block 1 ------- #
        #        Simple Step       #
        # ------------------------ #

        # Reach call of function c
        d.next()
        self.assertEqual(d.instruction_pointer, CALL_C_ADDRESS)

        # -------- Block 2 ------- #
        #        Skip a call       #
        # ------------------------ #

        d.next()
        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)

        d.kill()
        d.terminate()

    def test_next_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.instruction_pointer, TEST_ENTRYPOINT)

        # Reach call of function c
        d.next()

        self.assertEqual(d.instruction_pointer, CALL_C_ADDRESS)

        # -------- Block 1 ------- #
        #    Call with breakpoint  #
        # ------------------------ #

        # Set breakpoint
        test_breakpoint = d.breakpoint(TEST_BREAKPOINT_ADDRESS)
        
        d.next()

        # Check we hit the breakpoint
        self.assertEqual(d.instruction_pointer, TEST_BREAKPOINT_ADDRESS)
        self.assertEqual(test_breakpoint.hit_count, 1)

        d.kill()
        d.terminate()

    def test_next_breakpoint_hw(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.instruction_pointer, TEST_ENTRYPOINT)

        # Reach call of function c
        d.next()

        self.assertEqual(d.instruction_pointer, CALL_C_ADDRESS)

        # -------- Block 1 ------- #
        #    Call with breakpoint  #
        # ------------------------ #

        # Set breakpoint
        test_breakpoint = d.breakpoint(TEST_BREAKPOINT_ADDRESS, hardware=True)

        d.next()

        # Check we hit the breakpoint
        self.assertEqual(d.instruction_pointer, TEST_BREAKPOINT_ADDRESS)
        self.assertEqual(test_breakpoint.hit_count, 1)

        d.kill()
        d.terminate()
