#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys
from unittest import TestCase
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


match PLATFORM:
    case "amd64":
        READ_NUM = 0
        MMAP_NUM = 9
        MMAP_NAME = "mmap"
    case "aarch64":
        READ_NUM = 63
        MMAP_NUM = 222
        MMAP_NAME = "mmap"
    case "i386":
        READ_NUM = 3
        MMAP_NUM = 192
        MMAP_NAME = "mmap_pgoff"
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")

class PPrintSyscallsTest(TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__

    def test_pprint_syscalls_generic(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertIn("0xe", self.capturedOutput.getvalue())
        self.assertIn("0x8", self.capturedOutput.getvalue())
        self.assertIn("0x400", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_syscalls_with_statement(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()
        with d.pprint_syscalls_context(True):
            r.sendline(b"provola")

            d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertIn("0xe", self.capturedOutput.getvalue())
        self.assertIn("0x8", self.capturedOutput.getvalue())
        self.assertIn("0x400", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_handle_syscalls(self):
        def on_enter_read(d, sh):
            pass

        def on_exit_read(d, sh):
            d.syscall_return = 0xDEADBEEF

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()
        d.pprint_syscalls = True

        d.handle_syscall("read", on_enter_read, on_exit_read)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())
        self.assertIn(
            "(callback) \x1b[94mread\x1b[39m", self.capturedOutput.getvalue()
        )

        self.assertIn(
            "= \x1b[33m\x1b[9m0x8\x1b[0m \x1b[33m0xdeadbeef\x1b[0m",
            self.capturedOutput.getvalue(),
        )

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("callback"), 1)

    def test_pprint_hijack_syscall(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        d.pprint_syscalls = True

        d.hijack_syscall("getcwd", "write")

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())
        self.assertIn(
            "(hijacked) \x1b[9m\x1b[94mgetcwd\x1b[39m",
            self.capturedOutput.getvalue(),
        )

        self.assertEqual(
            self.capturedOutput.getvalue().count("write"), 3
        )  # 2 from the test, 1 from the hijack
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("hijacked"), 1)

    def test_pprint_which_syscalls_pprint_after(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        d.pprint_syscalls = True
        d.syscalls_to_pprint = [READ_NUM, "write", MMAP_NUM]  # after d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)

    def test_pprint_which_syscalls_pprint_before(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))
        r = d.run()

        d.syscalls_to_pprint = [READ_NUM, "write", MMAP_NUM]  # before d.pprint_syscalls = True
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)

    def test_pprint_which_syscalls_pprint_after_and_before(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))
        r = d.run()

        d.syscalls_to_pprint = [READ_NUM, "write", MMAP_NUM]
        d.pprint_syscalls = True
        d.syscalls_to_pprint = ["write", MMAP_NUM]

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertNotIn("getcwd", self.capturedOutput.getvalue())
        self.assertNotIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("write"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count(MMAP_NAME), 1)

    def test_pprint_which_syscalls_not_pprint_after(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))
        r = d.run()

        d.pprint_syscalls = True
        d.syscalls_to_not_pprint = [READ_NUM, "write", MMAP_NUM]

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertNotIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_which_syscalls_not_pprint_before(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))
        r = d.run()

        d.syscalls_to_not_pprint = [READ_NUM, "write", MMAP_NUM]
        d.pprint_syscalls = True

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertNotIn("read", self.capturedOutput.getvalue())
        self.assertNotIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)

    def test_pprint_which_syscalls_not_pprint_after_and_before(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))
        r = d.run()

        d.syscalls_to_not_pprint = [READ_NUM, "write", MMAP_NUM]
        d.pprint_syscalls = True
        d.syscalls_to_not_pprint = ["write", MMAP_NUM]

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertNotIn("write", self.capturedOutput.getvalue())
        self.assertIn("read", self.capturedOutput.getvalue())
        self.assertNotIn(MMAP_NAME, self.capturedOutput.getvalue())
        self.assertIn("getcwd", self.capturedOutput.getvalue())
        self.assertIn("exit_group", self.capturedOutput.getvalue())

        self.assertEqual(self.capturedOutput.getvalue().count("read"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("getcwd"), 1)
        self.assertEqual(self.capturedOutput.getvalue().count("exit_group"), 1)
