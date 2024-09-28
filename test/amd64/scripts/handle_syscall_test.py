#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import os
import sys
import unittest

from libdebug import debugger


class HandleSyscallTest(unittest.TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput
        sys.stderr = self.capturedOutput

        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_handler.close()

    def test_handles(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall("mmap", None, on_exit_mmap)
        handler3 = d.handle_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_with_pprint(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall("mmap", None, on_exit_mmap)
        handler3 = d.handle_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()
        d.wait()

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_disabling(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(1, on_enter_write, None)
        handler2 = d.handle_syscall(9, None, on_exit_mmap)
        handler3 = d.handle_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        handler1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(handler1.hit_count, 1)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_disabling_with_pprint(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(1, on_enter_write, None)
        handler2 = d.handle_syscall(9, None, on_exit_mmap)
        handler3 = d.handle_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        handler1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(handler1.hit_count, 1)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_overwrite(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, sh):
            nonlocal write_count_first

            self.assertTrue(sh.syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, sh):
            nonlocal write_count_second

            self.assertTrue(sh.syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(1, on_enter_write_first, None)
        handler2 = d.handle_syscall(9, None, on_exit_mmap)
        handler3 = d.handle_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        handler1_2 = d.handle_syscall(1, on_enter_write_second, None)

        d.cont()

        d.kill()

        self.assertEqual(write_count_first, 1)
        self.assertEqual(write_count_second, 1)
        self.assertEqual(handler1_1.hit_count, 2)
        self.assertEqual(handler1_2.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

        self.assertIn("WARNING", self.log_capture_string.getvalue())
        self.assertIn(
            "Syscall write is already handled by a user-defined handler. Overriding it.",
            self.log_capture_string.getvalue(),
        )

    def test_handle_overwrite_with_pprint(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, sh):
            nonlocal write_count_first

            self.assertTrue(sh.syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, sh):
            nonlocal write_count_second

            self.assertTrue(sh.syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(1, on_enter_write_first, None)
        handler2 = d.handle_syscall(9, None, on_exit_mmap)
        handler3 = d.handle_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        handler1_2 = d.handle_syscall(1, on_enter_write_second, None)

        d.cont()

        d.kill()

        self.assertEqual(write_count_first, 1)
        self.assertEqual(write_count_second, 1)
        self.assertEqual(handler1_1.hit_count, 2)
        self.assertEqual(handler1_2.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

        self.assertIn("WARNING", self.log_capture_string.getvalue())
        self.assertIn(
            "Syscall write is already handled by a user-defined handler. Overriding it.",
            self.log_capture_string.getvalue(),
        )

    def test_handles_sync(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall("mmap")
        handler3 = d.handle_syscall("getcwd")

        r.sendline(b"provola")

        while not d.dead:
            d.cont()
            d.wait()
            if handler1.hit_on_enter(d):
                on_enter_write(d, handler1)
            elif handler2.hit_on_exit(d):
                on_exit_mmap(d, handler2)
            elif handler3.hit_on_enter(d):
                on_enter_getcwd(d, handler3)
            elif handler3.hit_on_exit(d):
                on_exit_getcwd(d, handler3)

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_sync_with_pprint(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall("mmap")
        handler3 = d.handle_syscall("getcwd")

        d.pprint_syscalls = True

        r.sendline(b"provola")

        while not d.dead:
            d.cont()
            d.wait()
            if handler1.hit_on_enter(d):
                on_enter_write(d, handler1)
            elif handler2.hit_on_exit(d):
                on_exit_mmap(d, handler2)
            elif handler3.hit_on_enter(d):
                on_enter_getcwd(d, handler3)
            elif handler3.hit_on_exit(d):
                on_exit_getcwd(d, handler3)

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_sync_hit_on(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall("mmap")
        handler3 = d.handle_syscall("getcwd")

        r.sendline(b"provola")

        on_enter_1 = True
        on_exit_2 = True
        on_enter_3 = True

        while not d.dead:
            d.cont()
            d.wait()
            if handler1.hit_on(d):
                if on_enter_1:
                    on_enter_write(d, handler1)
                    on_enter_1 = False
                else:
                    on_enter_1 = True
            elif handler2.hit_on(d):
                if on_exit_2:
                    on_exit_2 = False
                else:
                    on_exit_mmap(d, handler2)
                    on_exit_2 = True
            elif handler3.hit_on(d):
                if on_enter_3:
                    on_enter_getcwd(d, handler3)
                    on_enter_3 = False
                else:
                    on_exit_getcwd(d, handler3)
                    on_enter_3 = True

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_empty_callback(self):
        d = debugger("binaries/handle_syscall_test")

        r = d.run()

        handler1 = d.handle_syscall("write", True, None)
        handler2 = d.handle_syscall("mmap", None, True)
        handler3 = d.handle_syscall("getcwd", True, True)

        r.sendline(b"provola")

        d.cont()
        d.wait()

        d.kill()
        d.terminate()

        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_all_syscalls(self):
        d = debugger("binaries/handle_syscall_test")

        for value in ["all", "*", "ALL", -1, "pkm"]:
            r = d.run()

            enter_count = 0
            exit_count = 0

            def on_enter_handler(t, hs):
                nonlocal enter_count
                enter_count += 1

            def on_exit_handler(t, hs):
                nonlocal exit_count
                exit_count += 1

            handler = d.handle_syscall(
                value, on_enter=on_enter_handler, on_exit=on_exit_handler
            )

            r.sendline(b"provola")

            d.cont()

            d.kill()

            # The exit_group syscall is handled only during entering for obvious reasons.
            # Hence, we have 6 enter events and 5 exit events. The hit_count is incremented
            # at the end of the syscall execution, so it is incremented only during the exit
            # event.
            self.assertEqual(handler.hit_count, 5)
            self.assertEqual(enter_count, 6)
            self.assertEqual(exit_count, 5)
