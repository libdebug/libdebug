#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE
from utils.thread_utils import FUN_ARG_0

from libdebug import debugger


match PLATFORM:
    case "amd64":
        TEST_BASIC_CALLBACK_STEP_OFFSET = 1
        TEST_CALLS_CALLBACK_STEP_OFFSET = 4
        TEST_CALLS_BP = 0x11a3
        TEST_CALLS_FINISH_OFFSET = 74
    case "aarch64":
        TEST_BASIC_CALLBACK_STEP_OFFSET = 4
        TEST_CALLS_CALLBACK_STEP_OFFSET = 4
        TEST_CALLS_BP = 0X7b8
        TEST_CALLS_FINISH_OFFSET = 68
    case "i386":
        TEST_BASIC_CALLBACK_STEP_OFFSET = 1
        TEST_CALLS_CALLBACK_STEP_OFFSET = 1
        TEST_CALLS_BP = 0x1213
        TEST_CALLS_FINISH_OFFSET = 93
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")

class CallbackTest(TestCase):
    def setUp(self):
        self.exceptions = []
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self):
        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_handler.close()

    def test_callback_simple(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        def callback(thread, bp):
            global hit

            try:
                self.assertEqual(bp.hit_count, 1)
                self.assertTrue(bp.hit_on(thread))
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()

        d.kill()
        d.terminate()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_simple_hardware(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        def callback(thread, bp):
            global hit

            try:
                self.assertEqual(bp.hit_count, 1)
                self.assertTrue(bp.hit_on(thread))
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("register_test", callback=callback, hardware=True)

        d.cont()

        d.kill()
        d.terminate()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_memory(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        def callback(thread, bp):
            global hit

            prev = bytes(range(256))
            try:
                self.assertEqual(bp.address, thread.instruction_pointer)
                self.assertEqual(bp.hit_count, 1)
                self.assertEqual(thread.memory[FUN_ARG_0(thread), 256], prev)

                thread.memory[FUN_ARG_0(thread) + 128 :] = b"abcd123456"
                prev = prev[:128] + b"abcd123456" + prev[138:]

                self.assertEqual(thread.memory[FUN_ARG_0(thread), 256], prev)
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("change_memory", callback=callback)

        d.cont()

        d.kill()
        d.terminate()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_exception(self):
        self.exceptions.clear()

        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        def callback(thread, bp):
            # This operation should not raise any exception
            _ = FUN_ARG_0(thread)

        d.breakpoint("register_test", callback=callback, hardware=True)

        d.cont()

        d.kill()
        d.terminate()

    def test_callback_step(self):
        self.exceptions.clear()

        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        def callback(t, bp):
            self.assertEqual(t.instruction_pointer, bp.address)
            d.step()
            self.assertEqual(t.instruction_pointer, bp.address + TEST_BASIC_CALLBACK_STEP_OFFSET)

        d.breakpoint("register_test", callback=callback)

        d.cont()

        d.kill()
        d.terminate()
        
    def test_callback_next(self):
        d = debugger(RESOLVE_EXE("multiple_calls"))
        
        def callback(t, b):
            instruction_pointer_1 = t.instruction_pointer
            t.next()
            instruction_pointer_2 = t.instruction_pointer
            self.assertEqual(instruction_pointer_1 + TEST_CALLS_CALLBACK_STEP_OFFSET, instruction_pointer_2)

        r = d.run()

        d.bp("printMessage", hardware=True, callback=callback)

        bp2 = d.bp(TEST_CALLS_BP, hardware=True, file="binary")

        d.cont()

        for i in range(1, 11):
            self.assertEqual(r.recvline(), f"Function call number: {i}".encode())
            
        d.wait()

        self.assertTrue(bp2.hit_on(d))

        d.kill()
        d.terminate()
        
    def test_callback_finish(self):
        d = debugger(RESOLVE_EXE("multiple_calls"))
        
        def callback(t, b):
            instruction_pointer_1 = t.instruction_pointer
            t.finish()
            instruction_pointer_2 = t.instruction_pointer
            self.assertEqual(instruction_pointer_1 + TEST_CALLS_FINISH_OFFSET, instruction_pointer_2)

        r = d.run()

        d.bp("printMessage", hardware=True, callback=callback)

        bp2 = d.bp(TEST_CALLS_BP, hardware=True, file="binary")

        d.cont()

        for i in range(1, 11):
            self.assertEqual(r.recvline(), f"Function call number: {i}".encode())
            
        d.wait()

        self.assertTrue(bp2.hit_on(d))

        d.kill()
        d.terminate()
        
    def test_callback_finish(self):
        d = debugger(RESOLVE_EXE("multiple_calls"))
        
        def callback(t, b):
            instruction_pointer_1 = t.instruction_pointer
            t.step_until(instruction_pointer_1 + TEST_CALLS_CALLBACK_STEP_OFFSET)
            instruction_pointer_2 = t.instruction_pointer
            self.assertEqual(instruction_pointer_1 + TEST_CALLS_CALLBACK_STEP_OFFSET, instruction_pointer_2)

        r = d.run()

        d.bp("printMessage", hardware=True, callback=callback)

        bp2 = d.bp(TEST_CALLS_BP, hardware=True, file="binary")

        d.cont()

        for i in range(1, 11):
            self.assertEqual(r.recvline(), f"Function call number: {i}".encode())
            
        d.wait()

        self.assertTrue(bp2.hit_on(d))

        d.kill()
        d.terminate()

    def test_callback_pid_accessible(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        hit = False

        def callback(t, bp):
            nonlocal hit
            self.assertEqual(t.process_id, d.process_id)
            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()
        d.kill()
        d.terminate()

        self.assertTrue(hit)
    
    def test_callback_pid_accessible_alias(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        hit = False

        def callback(t, bp):
            nonlocal hit
            self.assertEqual(t.pid, d.pid)
            self.assertEqual(t.pid, t.process_id)
            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()
        d.kill()
        d.terminate()

        self.assertTrue(hit)
        
    def test_callback_tid_accessible_alias(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        hit = False

        def callback(t, bp):
            nonlocal hit
            self.assertEqual(t.tid, t.thread_id)
            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()
        d.kill()
        d.terminate()

        self.assertTrue(hit)
    
    def test_callback_empty(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        bp = d.breakpoint("register_test", callback=True)

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(bp.hit_count, 1)

    def test_raise_exception_in_bp_callback(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        def callback(_, __):
            raise Exception("Test exception")

        d.breakpoint("register_test", callback=callback)

        d.cont()

        d.wait()

        d.kill()
        d.terminate()

        # Check if the error was logged
        self.log_handler.flush()
        log_output = self.log_capture_string.getvalue()
        self.assertIn("Test exception", log_output)
        self.assertIn("ERROR", log_output)

    def test_raise_exception_in_all_callbacks(self):
        d = debugger(RESOLVE_EXE("run_pipes_test"))

        r = d.run()

        def callback(_, x):
            raise Exception(f"Test Exception for {type(x).__name__}")

        d.breakpoint("option_1", callback=callback)
        d.catch_signal(50, callback=callback)
        d.handle_syscall("write", on_enter=callback, on_exit=callback)

        d.cont()

        r.sendline(b"3")
        r.sendline(b"1")
        r.sendline(b"4")

        d.wait()

        while not d.dead:
            d.cont()
            d.wait()

        d.kill()
        d.terminate()

        self.log_handler.flush()
        log_output = self.log_capture_string.getvalue()

        # We should have printed "Test Exception for Breakpoint"
        self.assertIn("Test Exception for Breakpoint", log_output)

        # We should have printed "Test Exception for SignalCatcher"
        self.assertIn("Test Exception for Signal", log_output)

        # We should have printed "Test Exception for SyscallHandler" 82 times
        self.assertIn("Test Exception for Syscall", log_output)
        self.assertEqual(log_output.count("Test Exception for Syscall"), 82)

    def test_interrupt_inside_callback(self):
        d = debugger(RESOLVE_EXE("multiple_calls"))

        d.run()

        def callback(_, bp):
            if bp.hit_count == 5:
                d.interrupt()

        bp = d.breakpoint("printMessage", callback=callback)

        d.cont()
        d.wait()

        # We should be interrupted here
        self.assertEqual(bp.hit_count, 5)
        self.assertFalse(d.dead)

        bp.callback = None

        d.cont()
        d.wait()

        self.assertEqual(bp.hit_count, 6)
        self.assertFalse(d.dead)

        bp.callback = callback

        d.cont()
        d.wait()

        self.assertTrue(d.dead)

        d.kill()
        d.terminate()

    def test_bp_inside_callback(self):
        d = debugger(RESOLVE_EXE("backtrace_test"))

        d.run()

        bp2 = None
        bp3 = None

        def callback(_, bp):
            nonlocal bp2, bp3
            if bp.symbol == "function1":
                bp2 = d.breakpoint("function2")
                bp3 = d.breakpoint("function3", callback=callback, hardware=True)

        bp1 = d.breakpoint("function1", callback=callback)

        d.cont()
        d.wait()

        # We should be stopped at function2
        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)
        self.assertTrue(bp2.hit_on(d))

        d.cont()
        d.wait()

        self.assertTrue(d.dead)
        self.assertEqual(bp3.hit_count, 1)

        d.kill()
        d.terminate()

    def test_disable_self_inside_callback(self):
        d = debugger(RESOLVE_EXE("run_pipes_test"))

        r = d.run()

        def callback(_, x):
            x.disable()

        bp = d.bp("option_1", callback=callback)
        sc = d.catch_signal(50, callback=callback)
        sh1 = d.handle_syscall("rt_sigaction", on_enter=callback)
        sh2 = d.handle_syscall("write", on_exit=callback)

        d.cont()

        r.sendline(b"3")
        r.sendline(b"1")
        r.sendline(b"4")

        d.wait()

        self.assertEqual(bp.hit_count, 1)
        self.assertEqual(sc.hit_count, 1)
        self.assertEqual(sh1.hit_count, 1)
        self.assertEqual(sh2.hit_count, 1)
        self.assertTrue(d.dead)

        d.kill()
        d.terminate()

    def test_signal_and_syscalls_inside_callback(self):
        d = debugger(RESOLVE_EXE("run_pipes_test"))

        r = d.run()

        sc = None
        bp = None

        def rt_signaction_callback(_, sh):
            nonlocal sc, bp

            sc = d.catch_signal(50)
            bp = d.bp("option_1", callback=True)

        sh = d.handle_syscall("rt_sigaction", on_enter=rt_signaction_callback)

        d.cont()

        r.sendline(b"3")

        d.wait()

        # We should be stopped at SIGPROVOLA
        self.assertEqual(sc.hit_count, 1)
        self.assertTrue(sc.hit_on(d))

        d.cont()

        for _ in range(5):
            r.sendline(b"1") # Calls option_1

        r.sendline(b"4")

        d.wait()

        self.assertEqual(bp.hit_count, 5)
        self.assertEqual(sc.hit_count, 1)
        self.assertEqual(sh.hit_count, 1)

        d.kill()
        d.terminate()
