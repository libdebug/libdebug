#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys
import unittest

from libdebug import debugger


class PPrintSyscallsTest(unittest.TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__

    def test_pprint_syscalls_generic(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertIn("0xe", self.capturedOutput.getvalue())
        self.assertIn("0x8", self.capturedOutput.getvalue())
        self.assertIn("0x400", self.capturedOutput.getvalue())
        self.assertIn("0x26", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_syscalls_with_statement(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()
        with d.pprint_syscalls_context(True):
            r.sendline(b"provola")

            d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertIn("0xe", self.capturedOutput.getvalue())
        self.assertIn("0x8", self.capturedOutput.getvalue())
        self.assertIn("0x400", self.capturedOutput.getvalue())
        self.assertIn("0x26", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_syscalls_hooking(self):
        def on_enter_read(d, syscall_number):
            pass

        def on_exit_read(d, syscall_number):
            d.syscall_return = 0xDEADBEEF

        d = debugger("binaries/syscall_hook_test")

        r = d.run()
        d.pprint_syscalls = True

        d.hook_syscall("read", on_enter_read, on_exit_read)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())
        self.assertIn(
            "(user hooked) \x1b[94mread\x1b[39m", self.capturedOutput.getvalue()
        )

        self.assertIn(
            "= \x1b[33m\x1b[9m0x8\x1b[0m \x1b[33m0xdeadbeef\x1b[0m",
            self.capturedOutput.getvalue(),
        )

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("hooked"), 1)

    def test_pprint_hijack_syscall(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        d.pprint_syscalls = True

        d.hijack_syscall("getcwd", "write")

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())
        self.assertIn(
            "(user hijacked) \x1b[9m\x1b[94mgetcwd\x1b[39m",
            self.capturedOutput.getvalue(),
        )

        self.assertEqual(
            self.capturedOutput.getvalue().count("write"), 3
        )  # 2 from the test, 1 from the hijack
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("hijacked"), 1)

    def test_pprint_which_syscalls_pprint_after(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()

        d.pprint_syscalls = True
        d.syscalls_to_pprint = [0, "write", 9]  # after d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)

    def test_pprint_which_syscalls_pprint_before(self):
        d = debugger("binaries/syscall_hook_test")
        r = d.run()

        d.syscalls_to_pprint = [0, "write", 9]  # before d.pprint_syscalls = True
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)

    def test_pprint_which_syscalls_pprint_after_and_before(self):
        d = debugger("binaries/syscall_hook_test")
        r = d.run()

        d.syscalls_to_pprint = [0, "write", 9]
        d.pprint_syscalls = True
        d.syscalls_to_pprint = ["write", 9]

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertIn("mmap", self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("mmap"), 1)

    def test_pprint_which_syscalls_not_pprint_after(self):
        d = debugger("binaries/syscall_hook_test")
        r = d.run()

        d.pprint_syscalls = True
        d.syscalls_to_not_pprint = [0, "write", 9]

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertNotIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_which_syscalls_not_pprint_before(self):
        d = debugger("binaries/syscall_hook_test")
        r = d.run()

        d.syscalls_to_not_pprint = [0, "write", 9]
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertNotIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_which_syscalls_not_pprint_after_and_before(self):
        d = debugger("binaries/syscall_hook_test")
        r = d.run()

        d.syscalls_to_not_pprint = [0, "write", 9]
        d.pprint_syscalls = True
        d.syscalls_to_not_pprint = ["write", 9]

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertNotIn("mmap", self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)


if __name__ == "__main__":
    unittest.main()
