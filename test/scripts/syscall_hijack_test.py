#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys
from unittest import TestCase
from utils.binary_utils import BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        WRITE_NUM = 1
        BP_ADDRESS = 0x4011B0
        OUTPUT_STR = "0x402010"
    case "aarch64":
        WRITE_NUM = 64
        BP_ADDRESS = 0x9f0
        OUTPUT_STR = hex(BASE + 0xab0)
    case "i386":
        WRITE_NUM = 4
        BP_ADDRESS = 0x122f
        OUTPUT_STR = "0x402008"
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class SyscallHijackTest(TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__

    def test_hijack_syscall(self):
        def on_enter_write(d, sh):
            nonlocal write_count

            write_count += 1

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        d.hijack_syscall("getcwd", "write", recursive=True)

        # recursive is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=True)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

        write_count = 0
        r = d.run()

        d.hijack_syscall("getcwd", "write", recursive=False)

        # recursive is off, we expect the write handler to be called only twice
        handler = d.handle_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 2)

    def test_hijack_syscall_with_pprint(self):
        def on_enter_write(d, sh):
            nonlocal write_count

            write_count += 1

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.hijack_syscall("getcwd", "write", recursive=True)

        # recursive is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=True)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.hijack_syscall("getcwd", "write", recursive=False)

        # recursive is off, we expect the write handler to be called only twice
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=False)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 2)

    def test_hijack_handle_syscall(self):
        def on_enter_write(d, sh):
            nonlocal write_count

            write_count += 1

        def on_enter_getcwd(d, sh):
            d.syscall_number = WRITE_NUM

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        d.handle_syscall("getcwd", on_enter=on_enter_getcwd, recursive=True)

        # recursive is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

        write_count = 0
        r = d.run()

        d.handle_syscall("getcwd", on_enter=on_enter_getcwd, recursive=False)

        # recursive is off, we expect the write handler to be called only twice
        handler = d.handle_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 2)

    def test_hijack_handle_syscall_with_pprint(self):
        def on_enter_write(d, sh):
            nonlocal write_count

            write_count += 1

        def on_enter_getcwd(d, sh):
            d.syscall_number = WRITE_NUM

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.handle_syscall("getcwd", on_enter=on_enter_getcwd, recursive=True)

        # recursive hijack is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=True)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.handle_syscall("getcwd", on_enter=on_enter_getcwd, recursive=False)

        # recursive is off, we expect the write handler to be called only twice
        handler = d.handle_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 2)

    def test_hijack_syscall_args(self):
        write_buffer = None

        def on_enter_write(d, sh):
            nonlocal write_buffer
            nonlocal write_count

            write_buffer = d.syscall_arg1

            write_count += 1

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        # recursive hijack is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=True)
        d.breakpoint(BP_ADDRESS)

        d.cont()
        print(r.recvline())
        # Install the hijack. We expect to receive the "Hello, World!" string

        d.wait()

        d.hijack_syscall(
            "read",
            "write",
            syscall_arg0=0x1,
            syscall_arg1=write_buffer,
            syscall_arg2=14,
            recursive=True,
        )

        d.cont()

        print(r.recvline())

        d.kill()
        d.terminate()

        self.assertEqual(self.capturedOutput.getvalue().count("Hello, World!"), 2)
        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

    def test_hijack_syscall_args_with_pprint(self):
        write_buffer = None

        def on_enter_write(d, sh):
            nonlocal write_buffer
            nonlocal write_count

            write_buffer = d.syscall_arg1

            write_count += 1

        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True

        # recursive hijack is on, we expect the write handler to be called three times
        handler = d.handle_syscall("write", on_enter=on_enter_write, recursive=True)
        d.breakpoint(BP_ADDRESS)

        d.cont()
        print(r.recvline())
        # Install the hijack. We expect to receive the "Hello, World!" string

        d.wait()

        d.hijack_syscall(
            "read",
            "write",
            syscall_arg0=0x1,
            syscall_arg1=write_buffer,
            syscall_arg2=14,
            recursive=True,
        )

        d.cont()

        print(r.recvline())

        d.kill()
        d.terminate()

        self.assertEqual(self.capturedOutput.getvalue().count("Hello, World!"), 2)
        self.assertEqual(self.capturedOutput.getvalue().count("write"), 3)
        self.assertEqual(self.capturedOutput.getvalue().count(OUTPUT_STR), 3)
        self.assertEqual(write_count, handler.hit_count)
        self.assertEqual(handler.hit_count, 3)

    def test_hijack_syscall_wrong_args(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        d.run()

        with self.assertRaises(ValueError):
            d.hijack_syscall("read", "write", syscall_arg26=0x1)

        d.kill()
        d.terminate()

    def loop_detection_test(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()
        d.hijack_syscall("getcwd", "write", recursive=True)
        d.hijack_syscall("write", "getcwd", recursive=True)
        r.sendline(b"provola")

        # We expect an exception to be raised
        with self.assertRaises(RuntimeError):
            d.cont()
            d.wait()
            d.kill()

        r = d.run()
        d.hijack_syscall("getcwd", "write", recursive=False)
        d.hijack_syscall("write", "getcwd", recursive=True)
        r.sendline(b"provola")

        # We expect no exception to be raised
        d.cont()

        r = d.run()
        d.hijack_syscall("getcwd", "write", recursive=True)
        d.hijack_syscall("write", "getcwd", recursive=False)
        r.sendline(b"provola")

        # We expect no exception to be raised
        d.cont()

        d.kill()
        d.terminate()
