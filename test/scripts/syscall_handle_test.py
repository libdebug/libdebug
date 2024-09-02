#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import os
import sys
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE
from utils.thread_utils import FUN_RET_VAL

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        WRITE_NUM = 1
        MMAP_NUM = 9
        GETCWD_NUM = 0x4F
        BP_ADDRESS = 0x401196
    case "aarch64":
        WRITE_NUM = 64
        MMAP_NUM = 222
        GETCWD_NUM = 17
        BP_ADDRESS = 0x9d4
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class SyscallHandleTest(TestCase):
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
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall("mmap", None, on_exit_mmap)
        handler3 = d.handle_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_with_pprint(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall("mmap", None, on_exit_mmap)
        handler3 = d.handle_syscall("getcwd", on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.cont()
        d.wait()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_disabling(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(WRITE_NUM, on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, BP_ADDRESS)
        handler1.disable()

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, 1)
        self.assertEqual(handler1.hit_count, 1)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_disabling_with_pprint(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(WRITE_NUM, on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, BP_ADDRESS)
        handler1.disable()

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(write_count, 1)
        self.assertEqual(handler1.hit_count, 1)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handle_overwrite(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, sh):
            nonlocal write_count_first

            self.assertTrue(sh.syscall_number == WRITE_NUM)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, sh):
            nonlocal write_count_second

            self.assertTrue(sh.syscall_number == WRITE_NUM)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(WRITE_NUM, on_enter_write_first, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, BP_ADDRESS)
        handler1_2 = d.handle_syscall(WRITE_NUM, on_enter_write_second, None)

        d.cont()

        d.kill()
        d.terminate()

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
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        d.pprint_syscalls = True

        ptr = 0
        write_count_first = 0
        write_count_second = 0

        def on_enter_write_first(d, sh):
            nonlocal write_count_first

            self.assertTrue(sh.syscall_number == WRITE_NUM)
            self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_first += 1

        def on_enter_write_second(d, sh):
            nonlocal write_count_second

            self.assertTrue(sh.syscall_number == WRITE_NUM)
            self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
            self.assertEqual(d.syscall_arg0, 1)
            write_count_second += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.memory[d.syscall_arg0, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(WRITE_NUM, on_enter_write_first, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, BP_ADDRESS)
        handler1_2 = d.handle_syscall(WRITE_NUM, on_enter_write_second, None)

        d.cont()

        d.kill()
        d.terminate()

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
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
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
        d.terminate()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)
    
    def test_handles_sync_with_pprint(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        ptr = 0
        write_count = 0

        def on_enter_write(d, sh):
            nonlocal write_count

            if write_count == 0:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 13], b"Hello, World!")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1
            else:
                self.assertTrue(sh.syscall_number == WRITE_NUM)
                self.assertEqual(d.memory[d.syscall_arg1, 7], b"provola")
                self.assertEqual(d.syscall_arg0, 1)
                write_count += 1

        def on_exit_mmap(d, sh):
            self.assertTrue(sh.syscall_number == MMAP_NUM)

            nonlocal ptr

            ptr = FUN_RET_VAL(d)

        def on_enter_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
            self.assertEqual(d.syscall_arg0, ptr)

        def on_exit_getcwd(d, sh):
            self.assertTrue(sh.syscall_number == GETCWD_NUM)
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
        d.terminate()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)
