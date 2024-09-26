#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import string
import unittest

from libdebug import debugger


class CallbackTest(unittest.TestCase):
    def setUp(self):
        self.exceptions = []

    def test_callback_simple(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/basic_test")

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

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_simple_hardware(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/basic_test")

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

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_memory(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/memory_test")

        d.run()

        def callback(thread, bp):
            global hit

            prev = bytes(range(256))
            try:
                self.assertEqual(bp.address, thread.regs.pc)
                self.assertEqual(bp.hit_count, 1)
                self.assertEqual(thread.memory[thread.regs.x0, 256], prev)

                thread.memory[thread.regs.x0 + 128 :] = b"abcd123456"
                prev = prev[:128] + b"abcd123456" + prev[138:]

                self.assertEqual(thread.memory[thread.regs.x0, 256], prev)
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("change_memory", callback=callback)

        d.cont()

        d.kill()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_bruteforce(self):
        global flag
        global counter
        global new_counter

        flag = ""
        counter = 1
        new_counter = 0

        def brute_force(d, b):
            global new_counter
            try:
                new_counter = b.hit_count
            except Exception as e:
                self.exceptions.append(e)

        d = debugger("binaries/brute_test")
        while True:
            end = False
            for c in string.printable:
                r = d.run()

                d.breakpoint(0x974, callback=brute_force, hardware=True)
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                message = r.recvline()

                if new_counter > counter:
                    flag += c
                    counter = new_counter
                    d.kill()
                    break
                d.kill()
                if message == b"Giusto!":
                    flag += c
                    end = True
                    break
            if end:
                break

        self.assertEqual(flag, "BRUTINOBRUTONE")

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_exception(self):
        self.exceptions.clear()

        d = debugger("binaries/basic_test")

        d.run()

        def callback(thread, bp):
            # This operation should not raise any exception
            _ = d.regs.x0

        d.breakpoint("register_test", callback=callback, hardware=True)

        d.cont()

        d.kill()

    def test_callback_step(self):
        self.exceptions.clear()

        d = debugger("binaries/basic_test")

        d.run()

        def callback(t, bp):
            self.assertEqual(t.regs.pc, bp.address)
            d.step()
            self.assertEqual(t.regs.pc, bp.address + 4)

        d.breakpoint("register_test", callback=callback)

        d.cont()

        d.kill()

    def test_callback_pid_accessible(self):
        self.exceptions.clear()

        d = debugger("binaries/basic_test")

        d.run()

        hit = False

        def callback(t, bp):
            nonlocal hit
            self.assertEqual(t.process_id, d.process_id)
            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()
        d.kill()

        self.assertTrue(hit)
    
    def test_callback_pid_accessible_alias(self):
        self.exceptions.clear()

        d = debugger("binaries/basic_test")

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

        self.assertTrue(hit)
        
    def test_callback_tid_accessible_alias(self):
        self.exceptions.clear()

        d = debugger("binaries/basic_test")

        d.run()

        hit = False

        def callback(t, bp):
            nonlocal hit
            self.assertEqual(t.tid, t.thread_id)
            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()
        d.kill()

        self.assertTrue(hit)
    
    def test_callback_empty(self):
        self.exceptions.clear()


        d = debugger("binaries/basic_test")

        d.run()

        bp = d.breakpoint("register_test", callback=True)

        d.cont()

        d.kill()

        self.assertEqual(bp.hit_count, 1)

        if self.exceptions:
            raise self.exceptions[0]
