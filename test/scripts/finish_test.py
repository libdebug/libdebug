#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipIf
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
        
        MULTIPLE_CALLS_MIDDLE_ADDRESS = 0x1167
    case "aarch64":
        # Addresses of the dummy functions
        C_ADDRESS = BASE + 0x914
        B_ADDRESS = BASE + 0x8fc
        A_ADDRESS = BASE + 0x814

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = BASE + 0x938
        RETURN_POINT_FROM_A = BASE + 0x908

        BREAKPOINT_LOCATION = BASE + 0x920
        
        MULTIPLE_CALLS_MIDDLE_ADDRESS = 0x768
    case "i386":
        # Addresses of the dummy functions
        C_ADDRESS = BASE + 0x1262
        B_ADDRESS = BASE+ 0x124a
        A_ADDRESS = BASE + 0x11a9

        # Addresses of noteworthy instructions
        RETURN_POINT_FROM_C = BASE + 0x128f
        RETURN_POINT_FROM_A = BASE + 0x125f

        BREAKPOINT_LOCATION = BASE + 0x1277
        
        MULTIPLE_CALLS_MIDDLE_ADDRESS = 0x11bb
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class FinishTest(TestCase):
    def test_finish_exact_no_auto_interrupt_no_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=True, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=True, aslr=False)

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

        # Wait for the finish to complete
        d.wait() 
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

        # Wait for the finish to complete
        d.wait() 
        self.assertEqual(d.instruction_pointer, RETURN_POINT_FROM_A)

        d.kill()
        d.terminate()

    def test_finish_exact_no_auto_interrupt_breakpoint(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

        # Reach function c
        d.run()
        d.breakpoint(C_ADDRESS)
        d.cont()

        self.assertEqual(d.instruction_pointer, C_ADDRESS)

        stack_unwinder = stack_unwinding_provider(d._internal_debugger.arch)

        # We need to repeat the check for the three stages of the function preamble

        # Get current return address
        curr_srip = d.saved_ip
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.step()

        # Get current return address
        curr_srip = d.saved_ip
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.step()

        # Get current return address
        curr_srip = d.saved_ip
        self.assertEqual(curr_srip, RETURN_POINT_FROM_C)

        d.kill()
        d.terminate()

    def test_exact_breakpoint_return(self):
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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
        d = debugger(RESOLVE_EXE("finish_test"), auto_interrupt_on_command=False, aslr=False)

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

        d.step()

        # Check that nothing has broken
        self.assertFalse(d.dead)

        d.kill()
        d.terminate()

    def breakpoint_during_finish_backtrace_no_callbacks(self):        
        d = debugger(RESOLVE_EXE("multiple_calls"))
        d.run()

        # Put a breakpoint at the beginning of printMessage
        bp = d.bp("printMessage", hardware=True)
        
        # Put a breakpoint in the middle of printMessage
        bp2 = d.bp(MULTIPLE_CALLS_MIDDLE_ADDRESS, hardware=True, file="binary")

        d.cont()

        # We are now in printMessage
        self.assertTrue(bp.hit_on(d))
        instruction_pointer = d.regs.rip
        
        # Let's finish the function
        d.finish(heuristic="backtrace")
        
        # We expect to be at the second breakpoint
        self.assertTrue(bp2.hit_on(d))
        
        instruction_pointer_2 = d.regs.rip

        self.assertNotEqual(instruction_pointer, instruction_pointer_2)
        
        d.kill()
        d.terminate()
        
    def breakpoint_during_finish_step_no_callbacks(self):        
        d = debugger(RESOLVE_EXE("multiple_calls"))
        d.run()

        # Put a breakpoint at the beginning of printMessage
        bp = d.bp("printMessage", hardware=True)
        
        # Put a breakpoint in the middle of printMessage
        bp2 = d.bp(MULTIPLE_CALLS_MIDDLE_ADDRESS, hardware=True, file="binary")

        d.cont()

        # We are now in printMessage
        self.assertTrue(bp.hit_on(d))
        instruction_pointer = d.regs.rip
        
        # Let's finish the function
        d.finish(heuristic="step-mode")
        
        # We expect to be at the second breakpoint
        self.assertTrue(bp2.hit_on(d))
        
        instruction_pointer_2 = d.regs.rip

        self.assertNotEqual(instruction_pointer, instruction_pointer_2)
        
        d.kill()
        d.terminate()
        
    def breakpoint_during_finish_step_callback(self):
        entered = False
        def callback(t, bp):
            nonlocal entered
            entered = True
                
        d = debugger(RESOLVE_EXE("multiple_calls"))
        d.run()

        # Put a breakpoint at the beginning of printMessage
        bp = d.bp("printMessage", hardware=True)
        
        # Put a breakpoint in the middle of printMessage
        bp2 = d.bp(MULTIPLE_CALLS_MIDDLE_ADDRESS, hardware=True, file="binary", callback=callback)

        d.cont()

        # We are now in printMessage
        self.assertTrue(bp.hit_on(d))
        instruction_pointer = d.regs.rip
        
        # Let's finish the function
        d.finish(heuristic="step-mode")
        
        # We expect to be at the second breakpoint
        self.assertTrue(bp2.hit_on(d))
        
        # Check that the callback was called
        self.assertTrue(entered)
        
        instruction_pointer_2 = d.regs.rip

        self.assertNotEqual(instruction_pointer, instruction_pointer_2)
        
        d.kill()
        d.terminate()
        
    def breakpoint_during_finish_backtrace_callback(self):
        entered = False
        def callback(t, bp):
            nonlocal entered
            entered = True
                
        d = debugger(RESOLVE_EXE("multiple_calls"))
        d.run()

        # Put a breakpoint at the beginning of printMessage
        bp = d.bp("printMessage", hardware=True)
        
        # Put a breakpoint in the middle of printMessage
        bp2 = d.bp(MULTIPLE_CALLS_MIDDLE_ADDRESS, hardware=True, file="binary", callback=callback)

        d.cont()

        # We are now in printMessage
        self.assertTrue(bp.hit_on(d))
        instruction_pointer = d.regs.rip
        
        # Let's finish the function
        d.finish(heuristic="backtrace")
        
        # We expect to be at the second breakpoint
        self.assertTrue(bp2.hit_on(d))
        
        # Check that the callback was called
        self.assertTrue(entered)
        
        instruction_pointer_2 = d.regs.rip

        self.assertNotEqual(instruction_pointer, instruction_pointer_2)
        
        d.kill()
        d.terminate()
        
    def breakpoint_during_finish_backtrace_callback_both(self):
        entered = False
        def callback(t, bp):
            nonlocal entered
            entered = True
        
        def callback_finish(t, bp):
            global instruction_pointer, instruction_pointer_2
            instruction_pointer = t.regs.rip
            t.finish(heuristic="backtrace")
            instruction_pointer_2 = t.regs.rip
                
        d = debugger(RESOLVE_EXE("multiple_calls"))
        d.run()

        # Put a breakpoint at the beginning of printMessage
        bp = d.bp("printMessage", hardware=True, callback=callback_finish)
        
        # Put a breakpoint in the middle of printMessage
        bp2 = d.bp(MULTIPLE_CALLS_MIDDLE_ADDRESS, hardware=True, file="binary", callback=callback)

        d.cont()
        
        # We expect to be at the second breakpoint
        self.assertTrue(bp2.hit_on(d))
        
        # Check that the callback was called
        self.assertTrue(entered)
        
        self.assertNotEqual(instruction_pointer, instruction_pointer_2)
        
        d.kill()
        d.terminate()