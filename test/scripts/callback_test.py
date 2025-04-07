#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

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

        assert bp2.hit_on(d)

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

        assert bp2.hit_on(d)

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

        assert bp2.hit_on(d)

        d.kill()
        d.terminate()

    def test_callback_pid_accessible(self):
        self.exceptions.clear()

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
        self.exceptions.clear()

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
        self.exceptions.clear()

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
        self.exceptions.clear()

        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        bp = d.breakpoint("register_test", callback=True)

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(bp.hit_count, 1)

        if self.exceptions:
            raise self.exceptions[0]
