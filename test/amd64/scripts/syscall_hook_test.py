#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import unittest

from libdebug import debugger


class SyscallHookTest(unittest.TestCase):
    def test_hooks(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.rsi, 13], b"Hello, World!")
                self.assertEqual(d.rdi, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.rsi, 7], b"provola")
                self.assertEqual(d.rdi, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.rdi, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.rdi, 8], os.getcwd()[:8].encode())

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
                self.assertEqual(d.memory[d.rsi, 13], b"Hello, World!")
                self.assertEqual(d.rdi, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 1)
                self.assertEqual(d.memory[d.rsi, 7], b"provola")
                self.assertEqual(d.rdi, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 9)

            nonlocal ptr

            ptr = d.rax

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.rdi, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x4F)
            self.assertEqual(d.memory[d.rdi, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall(1, on_enter_write, None)
        hook2 = d.hook_syscall(9, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x4F, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(0x401196)

        d.cont()

        d.wait()

        self.assertEqual(d.rip, 0x401196)
        hook1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(hook1.hit_count, 1)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)
