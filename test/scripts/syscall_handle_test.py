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
from utils.binary_utils import PLATFORM, RESOLVE_EXE
from utils.thread_utils import FUN_RET_VAL

from libdebug import debugger


match PLATFORM:
    case "amd64":
        WRITE_NUM = 1
        MMAP_NUM = 9
        GETCWD_NUM = 0x4F
        BP_ADDRESS = 0x401196
        MMAP_NAME = "mmap"
    case "aarch64":
        WRITE_NUM = 64
        MMAP_NUM = 222
        GETCWD_NUM = 17
        BP_ADDRESS = 0x9d4
        MMAP_NAME = "mmap"
    case "i386":
        WRITE_NUM = 4
        MMAP_NUM = 192
        GETCWD_NUM = 183
        BP_ADDRESS = 0x121a
        MMAP_NAME = "mmap_pgoff"
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NAME, None, on_exit_mmap)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write", on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NAME, None, on_exit_mmap)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(WRITE_NUM, on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        bp = d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, bp.address)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall(WRITE_NUM, on_enter_write, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        bp = d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, bp.address)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(WRITE_NUM, on_enter_write_first, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        bp = d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, bp.address)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1_1 = d.handle_syscall(WRITE_NUM, on_enter_write_first, None)
        handler2 = d.handle_syscall(MMAP_NUM, None, on_exit_mmap)
        handler3 = d.handle_syscall(GETCWD_NUM, on_enter_getcwd, on_exit_getcwd)

        r.sendline(b"provola")

        bp = d.breakpoint(BP_ADDRESS)

        d.cont()

        d.wait()

        self.assertEqual(d.instruction_pointer, bp.address)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall(MMAP_NAME)
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall(MMAP_NAME)
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

    def test_handles_sync_hit_on(self):
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
            self.assertEqual(d.memory[ptr, 8], os.getcwd()[:8].encode())

        handler1 = d.handle_syscall("write")
        handler2 = d.handle_syscall(MMAP_NAME)
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
        d.terminate()

        self.assertEqual(write_count, 2)
        self.assertEqual(handler1.hit_count, 2)
        self.assertEqual(handler2.hit_count, 1)
        self.assertEqual(handler3.hit_count, 1)

    def test_handles_empty_callback(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        handler1 = d.handle_syscall("write", True, None)
        handler2 = d.handle_syscall(MMAP_NAME, None, True)
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
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

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

        d.terminate()

    def test_handle_sync_single_thread(self):
        d = debugger(RESOLVE_EXE("io_thread_cont_test"))

        r = d.run()
        
        d.cont()
        
        messages = []
        for _ in range(5):
            messages.append(r.recvline())
            
        self.assertIn(b"Thread 1 is running...", messages)
        self.assertIn(b"Thread 2 is running...", messages)
        self.assertIn(b"Thread 3 is running...", messages)
        self.assertIn(b"Thread 4 is running...", messages)
        self.assertIn(b"Thread 5 is running...", messages)
        
        d.interrupt()
        
        # Install a handler for the write syscall on a specific thread
        target = d.threads[2]
        other_threads = d.threads.copy()
        other_threads.remove(target)
        handler = target.handle_syscall("write")
                
        # Wait for the target thread to hit the write syscall
        d.cont()
        
        r.sendline(b"provola")
        
        d.wait()
        
        # On enter
        self.assertTrue(handler.hit_on(target))
        self.assertTrue(handler.hit_on_enter(target))
        self.assertFalse(handler.hit_on_exit(target))
        
        for t in other_threads:
            self.assertFalse(handler.hit_on(t))
            self.assertFalse(handler.hit_on_enter(t))
            self.assertFalse(handler.hit_on_exit(t))
        
        # Continue the process and wait for the target thread to exit the syscall
        d.cont()
        d.wait()
        
        # On exit
        self.assertTrue(handler.hit_on(target))
        self.assertTrue(handler.hit_on_exit(target))
        self.assertFalse(handler.hit_on_enter(target))
        
        for t in other_threads:
            self.assertFalse(handler.hit_on(t))
            self.assertFalse(handler.hit_on_exit(t))
            self.assertFalse(handler.hit_on_enter(t))
        
        # We can disable the handler
        handler.disable()
        
        # Continue the process
        d.cont()
        
        messages = []
        for _ in range(5):
            messages.append(r.recvline())
            
        self.assertIn(b"Thread 1 finished.", messages)
        self.assertIn(b"Thread 2 finished.", messages)
        self.assertIn(b"Thread 3 finished.", messages)
        self.assertIn(b"Thread 4 finished.", messages)
        self.assertIn(b"Thread 5 finished.", messages)
        
        d.wait()
        d.kill()
        
        self.assertEqual(handler.hit_count, 1)
        
        d.terminate()
        
    def test_handle_async_thread_scoped(self):
        def callback(t, hs):
            self.assertTrue(t.thread_id == target.tid)
        
        d = debugger(RESOLVE_EXE("io_thread_cont_test"))

        r = d.run()
        
        d.cont()
        
        messages = []
        for _ in range(5):
            messages.append(r.recvline())
            
        self.assertIn(b"Thread 1 is running...", messages)
        self.assertIn(b"Thread 2 is running...", messages)
        self.assertIn(b"Thread 3 is running...", messages)
        self.assertIn(b"Thread 4 is running...", messages)
        self.assertIn(b"Thread 5 is running...", messages)
        
        d.interrupt()
        
        # Install a handler for the write syscall on a specific thread
        target = d.threads[2]
        handler = target.handle_syscall("write", on_enter=callback, on_exit=callback)
                
        # Wait for the target thread to hit the write syscalls
        d.cont()
        
        r.sendline(b"provola")
        
        d.wait()
        
        messages = []
        for _ in range(5):
            messages.append(r.recvline())
            
        self.assertIn(b"Thread 1 finished.", messages)
        self.assertIn(b"Thread 2 finished.", messages)
        self.assertIn(b"Thread 3 finished.", messages)
        self.assertIn(b"Thread 4 finished.", messages)
        self.assertIn(b"Thread 5 finished.", messages)
        
        d.wait()
        d.kill()
        
        # We expect two write syscalls in the target thread
        self.assertEqual(handler.hit_count, 2)
        
        d.terminate()