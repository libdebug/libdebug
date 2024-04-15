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
                self.assertTrue(syscall_number == 0x40)
                self.assertEqual(d.memory[d.x1, 13], b"Hello, World!")
                self.assertEqual(d.x0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 0x40)
                self.assertEqual(d.memory[d.x1, 7], b"provola")
                self.assertEqual(d.x0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 0xde)

            nonlocal ptr

            ptr = d.x0

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x11)
            self.assertEqual(d.x0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x11)
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall("write", on_enter_write, None)
        hook2 = d.hook_syscall("mmap", None, on_exit_mmap)
        hook3 = d.hook_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, 2)
        self.assertEqual(hook1.hit_count, 2)
        # TODO: re-enable this check after we have continue_to_binary_entrypoint working
        # self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)

    def test_hook_disabling(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, syscall_number):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(syscall_number == 0x40)
                self.assertEqual(d.memory[d.x1, 13], b"Hello, World!")
                self.assertEqual(d.x0, 1)
                write_count += 1
            else:
                self.assertTrue(syscall_number == 0x40)
                self.assertEqual(d.memory[d.x1, 7], b"provola")
                self.assertEqual(d.x0, 1)
                write_count += 1

        def on_exit_mmap(d, syscall_number):
            self.assertTrue(syscall_number == 0xde)

            nonlocal ptr

            ptr = d.x0

        def on_enter_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x11)
            self.assertEqual(d.x0, ptr)

        def on_exit_getcwd(d, syscall_number):
            self.assertTrue(syscall_number == 0x11)
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        hook1 = d.hook_syscall(0x40, on_enter_write, None)
        hook2 = d.hook_syscall(0xde, None, on_exit_mmap)
        hook3 = d.hook_syscall(0x11, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        bp = d.breakpoint(0x930)

        d.cont()

        d.wait()

        self.assertEqual(d.pc, bp.address)
        hook1.disable()

        d.cont()

        d.kill()

        self.assertEqual(write_count, 1)
        self.assertEqual(hook1.hit_count, 1)
        # TODO: re-enable this check after we have continue_to_binary_entrypoint working
        # self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(hook3.hit_count, 1)
