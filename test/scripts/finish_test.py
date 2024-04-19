#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Francesco Panebianco.
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

# Addresses of the dummy functions
C_ADDRESS = 0x4011e3
B_ADDRESS = 0x4011d2
A_ADDRESS = 0x401146

# Addresses of noteworthy instructions
RETURN_POINT_FROM_C = 0x401202
RETURN_POINT_FROM_A = 0x4011e0

class FinishTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_finish_exact_no_auto_interrupt_no_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.rip, C_ADDRESS)

        # Finish function c
        d.finish(exact=True)

        self.assertTrue(d.rip == RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        # The first breakpoint is C, skip it
        d.cont()
        d.cont()

        self.assertEqual(d.rip, A_ADDRESS)

        # Finish function c
        d.finish(exact=True)

        self.assertTrue(d.rip == RETURN_POINT_FROM_A)

        d.kill()

    def test_finish_heuristic_no_auto_interrupt_no_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.rip, C_ADDRESS)

        # Finish function c
        d.finish(exact=False)

        self.assertTrue(d.rip == RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        # The first breakpoint is C, skip it
        d.cont()
        d.cont()

        self.assertEqual(d.rip, A_ADDRESS)

        # Finish function c
        d.finish(exact=False)

        self.assertTrue(d.rip == RETURN_POINT_FROM_A)

        d.kill()

    def test_finish_exact_auto_interrupt_no_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=True)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.rip, C_ADDRESS)

        # Finish function c
        d.finish(exact=True)

        self.assertTrue(d.rip == RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        # The first breakpoint is C, skip it
        d.cont()
        d.wait()
        d.cont()
        d.wait()

        self.assertEqual(d.rip, A_ADDRESS)

        # Finish function c
        d.finish(exact=True)

        self.assertTrue(d.rip == RETURN_POINT_FROM_A)

        d.kill()

    def test_finish_heuristic_auto_interrupt_no_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=True)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.rip, C_ADDRESS)

        # Finish function c
        d.finish(exact=False)

        self.assertTrue(d.rip == RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        # The first breakpoint is C, skip it
        d.cont()
        d.wait()
        d.cont()
        d.wait()

        self.assertEqual(d.rip, A_ADDRESS)

        # Finish function c
        d.finish(exact=False)

        self.assertTrue(d.rip == RETURN_POINT_FROM_A)

        d.kill()

    def test_finish_exact_no_auto_interrupt_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.rip, C_ADDRESS)

        d.breakpoint(A_ADDRESS)

        # Finish function c
        d.finish(exact=True)

        self.assertTrue(d.rip == A_ADDRESS)

        d.kill()

    def test_finish_heuristic_no_auto_interrupt_breakpoint(self):
        d = debugger("binaries/finish_test", auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.rip, C_ADDRESS)

        d.breakpoint(A_ADDRESS)

        # Finish function c
        d.finish(exact=False)

        self.assertTrue(d.rip == A_ADDRESS)

        d.kill()