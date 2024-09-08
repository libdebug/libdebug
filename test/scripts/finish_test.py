#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import PLATFORM, BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider


match PLATFORM:
    case "amd64":
        # Addresses of the dummy functions
        C_ADDRESS = 0x4011e3
        B_ADDRESS = 0x4011d2
        A_ADDRESS = 0x401146

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = 0x401202
        RETURN_POINT_FROM_A = 0x4011e0

        BREAKPOINT_LOCATION = 0x4011f1
    case "aarch64":
        # Addresses of the dummy functions
        C_ADDRESS = BASE + 0x914
        B_ADDRESS = BASE + 0x8fc
        A_ADDRESS = BASE + 0x814

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = BASE + 0x938
        RETURN_POINT_FROM_A = BASE + 0x908

        BREAKPOINT_LOCATION = BASE + 0x920
    case "i386":
        # Addresses of the dummy functions
        C_ADDRESS = BASE + 0x1262
        B_ADDRESS = BASE+ 0x124a
        A_ADDRESS = BASE + 0x11a9

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = BASE + 0x128f
        RETURN_POINT_FROM_A = BASE + 0x125f

        BREAKPOINT_LOCATION = BASE + 0x1277
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class FinishTest(TestCase):
    def test_finish_exact_no_auto_interrupt_no_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        # Finish function c
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, A_ADDRESS)

        # Finish function a
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_A)

        d.kill()
        d.terminate()

    def test_finish_heuristic_no_auto_interrupt_no_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        # Finish function c
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, A_ADDRESS)

        # Finish function a
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_A)

        d.kill()
        d.terminate()

    def test_finish_exact_auto_interrupt_no_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=True)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        # Finish function c
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.instruction_pointer, A_ADDRESS)

        # Finish function a
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_A)

        d.kill()
        d.terminate()

    def test_finish_heuristic_auto_interrupt_no_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=True)

        # ------------------ Block 1 ------------------ #
        #       Return from the first function call     #
        # --------------------------------------------- #

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        # Finish function c
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)

        d.kill()

        # ------------------ Block 2 ------------------ #
        #       Return from the nested function call    #
        # --------------------------------------------- #

        # Reach function a
        d.run()
        d.breakpoint(A_ADDRESS)
        d.cont()
        d.wait()

        self.assertEqual(d.instruction_pointer, A_ADDRESS)

        # Finish function a
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_A)

        d.kill()
        d.terminate()

    def test_finish_exact_no_auto_interrupt_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        d.breakpoint(A_ADDRESS)

        # Finish function c
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, A_ADDRESS, f"Expected {hex(A_ADDRESS)} but got {hex(d.instruction_pointer)}")

        d.kill()
        d.terminate()

    def test_finish_heuristic_no_auto_interrupt_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        d.breakpoint(A_ADDRESS)

        # Finish function c
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, A_ADDRESS)

        d.kill()
        d.terminate()

    def test_heuristic_return_address(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        stack_unwinder = stack_unwinding_provider(d._internal_debugger.arch)

        # We need to repeat the check for the three stages of the function preamble

        # Get current return address
        curr_srip = stack_unwinder.get_return_address(d)
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.step()

        # Get current return address
        curr_srip = stack_unwinder.get_return_address(d)
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.step()

        # Get current return address
        curr_srip = stack_unwinder.get_return_address(d)
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.kill()
        d.terminate()

    def test_exact_breakpoint_return(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)


        # Place a breakpoint at a location inbetween
        d.breakpoint(BREAKPOINT_LOCATION)

        # Finish function c
        d.finish(heuristic="step-mode")

        self.assertEqual(d.instruction_pointer, BREAKPOINT_LOCATION)

        d.kill()
        d.terminate()

    def test_heuristic_breakpoint_return(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)


        # Place a breakpoint a location in between
        d.breakpoint(BREAKPOINT_LOCATION)

        # Finish function c
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, BREAKPOINT_LOCATION)

        d.kill()
        d.terminate()

    def test_breakpoint_collision(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        # Place a breakpoint at the same location as the return address
        d.breakpoint(RETURN_POINT_FROM_C)

        # Finish function c
        d.finish(heuristic="backtrace")

        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_C)
        self.assertFalse(d.running)

        d.step()

        # Check that the execution is still running and nothing has broken
        self.assertFalse(d.running)
        self.assertFalse(d.dead)

        d.kill()
        d.terminate()
