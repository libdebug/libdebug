#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
import unittest

from libdebug import debugger

TEST_ENTRYPOINT = 0xaaaaaaaa0930

# Addresses of the dummy functions
CALL_C_ADDRESS = 0xaaaaaaaa0934
TEST_BREAKPOINT_ADDRESS = 0xaaaaaaaa0920

# Addresses of noteworthy instructions
RETURN_POINT_FROM_C = 0xaaaaaaaa0938

class NextTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_next(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.regs.pc, TEST_ENTRYPOINT)

        # -------- Block 1 ------- #
        #        Simple Step       #
        # ------------------------ #

        # Reach call of function c
        d.next()
        self.assertEqual(d.regs.pc, CALL_C_ADDRESS)

        # -------- Block 2 ------- #
        #        Skip a call       #
        # ------------------------ #

        d.next()
        self.assertEqual(d.regs.pc, RETURN_POINT_FROM_C)

        d.kill()
        d.terminate()

    def test_next_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.regs.pc, TEST_ENTRYPOINT)

        # Reach call of function c
        d.next()

        self.assertEqual(d.regs.pc, CALL_C_ADDRESS)

        # -------- Block 1 ------- #
        #    Call with breakpoint  #
        # ------------------------ #

        # Set breakpoint
        test_breakpoint = d.breakpoint(TEST_BREAKPOINT_ADDRESS)

        d.next()

        # Check we hit the breakpoint
        self.assertEqual(d.regs.pc, TEST_BREAKPOINT_ADDRESS)
        self.assertEqual(test_breakpoint.hit_count, 1)

        d.kill()
        d.terminate()

    def test_next_breakpoint_hw(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)
        d.run()

        # Get to test entrypoint
        entrypoint_bp = d.breakpoint(TEST_ENTRYPOINT)
        d.cont()

        self.assertEqual(d.regs.pc, TEST_ENTRYPOINT)

        # Reach call of function c
        d.next()

        self.assertEqual(d.regs.pc, CALL_C_ADDRESS)

        # -------- Block 1 ------- #
        #    Call with breakpoint  #
        # ------------------------ #

        # Set breakpoint
        test_breakpoint = d.breakpoint(TEST_BREAKPOINT_ADDRESS, hardware=True)

        d.next()

        # Check we hit the breakpoint
        self.assertEqual(d.regs.pc, TEST_BREAKPOINT_ADDRESS)
        self.assertEqual(test_breakpoint.hit_count, 1)

        d.kill()
        d.terminate()