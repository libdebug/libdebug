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


class SyscallHookTest(unittest.TestCase):
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

    def test_hooks(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall("write", on_enter_write, None)
        hook2 = d.hook_syscall("mmap", None, on_exit_mmap)
        hook3 = d.hook_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

    def test_hooks_with_pprint(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall("write", on_enter_write, None)
        hook2 = d.hook_syscall("mmap", None, on_exit_mmap)
        hook3 = d.hook_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

    def test_hook_disabling(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall(1, on_enter_write, None)
        hook2 = d.hook_syscall(9, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        hook1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(hook1.hit_count, 1)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

    def test_hook_disabling_with_pprint(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall(1, on_enter_write, None)
        hook2 = d.hook_syscall(9, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        hook1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(hook1.hit_count, 1)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

    def test_hook_overwrite(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, syscall_number):
            nonlocal write_count_first

            self.assertTrue(syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, syscall_number):
            nonlocal write_count_second

            self.assertTrue(syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1_1 = d.hook_syscall(1, on_enter_write_first, None)
        hook2 = d.hook_syscall(9, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        hook1_2 = d.hook_syscall(1, on_enter_write_second, None)

        d.cont()

        d.kill()

        self.assertEqual(write_count_first, 1)
        self.assertEqual(write_count_second, 1)
        self.assertEqual(hook1_1.hit_count, 2)
        self.assertEqual(hook1_2.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

        self.assertIn("WARNING", self.log_capture_string.getvalue())
        self.assertIn(
            "Syscall write is already hooked by a user-defined hook. Overriding it.",
            self.log_capture_string.getvalue(),
        )

    def test_hook_overwrite_with_pprint(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, syscall_number):
            nonlocal write_count_first

            self.assertTrue(syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, syscall_number):
            nonlocal write_count_second

            self.assertTrue(syscall_number == 1)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.regs.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        hook1_1 = d.hook_syscall(1, on_enter_write_first, None)
        hook2 = d.hook_syscall(9, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.regs.rip, 0x401196)
        hook1_2 = d.hook_syscall(1, on_enter_write_second, None)

        d.cont()

        d.kill()

        self.assertEqual(write_count_first, 1)
        self.assertEqual(write_count_second, 1)
        self.assertEqual(hook1_1.hit_count, 2)
        self.assertEqual(hook1_2.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

        self.assertIn("WARNING", self.log_capture_string.getvalue())
        self.assertIn(
            "Syscall write is already hooked by a user-defined hook. Overriding it.",
            self.log_capture_string.getvalue(),
        )
