#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys
import uuid
import os
from unittest import TestCase
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger

# Relative address of main in each binary
match PLATFORM:
    case "amd64":
        BP_ADDRESS = 0x1119
    case "aarch64":
        BP_ADDRESS = 0x714
    case "i386":
        BP_ADDRESS = 0x117d
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class SyscallInvocationTest(TestCase):
    def test_no_handler(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        pipe = d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        # Retrieve binary map
        binary_map = d.maps.filter("binary")[0]

        # Invoke the syscall
        ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

        # Check the return value
        self.assertEqual(ret, 0x10)

        out = pipe.recv(4)

        # Check the output
        self.assertIn(b"\x7fELF", out)

        d.terminate()

    def test_sync_handler(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        # Retrieve binary map
        binary_map = d.maps.filter("binary")[0]

        handler = d.handle_syscall("write")

        # Invoke the syscall
        ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

        self.assertFalse(handler.hit_on_enter(d))
        self.assertFalse(handler.hit_on_exit(d))

        # Check the return value
        self.assertEqual(ret, 0x10)

        d.terminate()

    def test_async_handler(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        # Retrieve binary map
        binary_map = d.maps.filter("binary")[0]

        has_hit_enter = False
        has_hit_exit = False

        def handle_write_enter(t, h):
            nonlocal has_hit_enter
            has_hit_enter = True

        def handle_write_exit(t, h):
            nonlocal has_hit_exit
            has_hit_exit = True

        _ = d.handle_syscall("write", on_enter=handle_write_enter, on_exit=handle_write_exit)

        # Invoke the syscall
        ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

        # Check the return value
        self.assertEqual(ret, 0x10)

        # Check boolean flags
        self.assertTrue(has_hit_enter)
        self.assertTrue(has_hit_exit)

        d.terminate()

    # TODO: Decide the final behavior of the hijack
    def test_hijack_nullification(self):
        return
        d = debugger(RESOLVE_EXE("dummy_binary"))
        pipe = d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.hijack_syscall("write", "alarm")

        d.cont()
        d.wait()

        # Retrieve binary map
        binary_map = d.maps.filter("binary")[0]

        # Invoke the syscall
        ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

        # Check the return value
        self.assertEqual(ret, 0x10)

        out = pipe.recv(4)

        # Check the output
        self.assertIn(b"\x7fELF", out)

        d.terminate()

    def test_verify_correct_resume(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        # Retrieve binary map
        binary_map = d.maps.filter("binary")[0]

        ps = d.create_snapshot("full")
        prev_ip = d.instruction_pointer

        ip_page = d.maps.filter(prev_ip)[0]

        # Invoke the syscall
        ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

        # Check the return value
        self.assertEqual(ret, 0x10)

        sanity_check = 0

        # Check equality with the snapshot
        for reg in dir(d.regs):
            live_reg = getattr(d.regs, reg)

            try:
                snap_reg = getattr(ps.regs, reg)
            except AttributeError:
                # Skip internal stuff that is only present in the live process regs
                continue

            if not isinstance(live_reg, int):
                continue
            
            sanity_check += 1
            self.assertEqual(live_reg, snap_reg)

        self.assertGreater(sanity_check, 0)

        ip_page_original_contents = ps.maps.filter(ip_page.start)[0].content

        curr_page_contents = d.memory[ip_page.start:ip_page.end]
        self.assertEqual(ip_page_original_contents, curr_page_contents)

        # Check that the instruction pointer is the same
        self.assertEqual(d.instruction_pointer, prev_ip)

        d.terminate()

    def test_read(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        pipe = d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        code_map = d.maps.filter(d.instruction_pointer)[0]

        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        # unsigned long start, size_t len, unsigned long prot
        d.invoke_syscall("mprotect", code_map.start, code_map.size, PROT_READ | PROT_WRITE | PROT_EXEC)

        # Runtime patch
        # 0:  48 c7 c0 3c 00 00 00    mov    rax, 0x3c
        # 7:  48 c7 c7 7b 00 00 00    mov    rdi, 123
        # e:  0f 05                   syscall

        patch_code = b"\x48\xC7\xC0\x3C\x00\x00\x00\x48\xC7\xC7\x7B\x00\x00\x00\x0F\x05"

        # First instruction of main
        # <main>:	push   rbp
        # <main+1>:	mov    rbp,rsp
        # The syscall invocation will patch 2 bytes (0f 05) and restore them at the end
        # so we need to patch after the first instructions

        patch_offset = 4

        pipe.send(patch_code)

        # Invoke the syscall
        ret = d.invoke_syscall("read", 0, d.instruction_pointer + patch_offset, len(patch_code))

        # Check the return value
        self.assertEqual(ret, len(patch_code))

        d.cont()
        d.wait()

        self.assertTrue(d.dead)
        self.assertEqual(d.exit_code, 123)

        d.terminate()

    def test_file_open_close(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        rand_uuid = uuid.uuid4().hex

        filename = f"/tmp/{rand_uuid}"

        stack = d.maps.filter("stack")[0]
        d.memory[stack.start, len(filename) + 1, "absolute"] = filename.encode() + b"\x00"

        O_RDWR = 0o0000002
        O_CREAT = 0o0000100

        fd = d.invoke_syscall("open", stack.start, O_RDWR | O_CREAT, 0o666)

        self.assertEqual(fd, 3)

        # Assert existence of the file
        self.assertTrue(os.path.exists(f"/tmp/{rand_uuid}"))

        # Invoke the syscall
        ret = d.invoke_syscall("close", fd)

        self.assertEqual(ret, 0)

        # Assert that the file descriptor is closed
        self.assertFalse(os.path.exists(f"/proc/{d.pid}/fd/{fd}"))

        d.terminate()

    def test_mmap(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        MAP_PRIVATE = 0x2
        MAP_ANONYMOUS = 0x20

        prot = PROT_READ | PROT_WRITE | PROT_EXEC
        flags = MAP_PRIVATE | MAP_ANONYMOUS

        prev_num_maps = len(d.maps)

        # Invoke the syscall
        # unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off
        ret = d.invoke_syscall("mmap", 0xdeadc0de, 0x1000, prot, flags, -1, 0)

        # Page aligned address should be returned
        self.assertEqual(ret, 0xdeadc000)

        post_num_maps = len(d.maps)
        self.assertGreater(post_num_maps, prev_num_maps)

        # Check protection
        mmap_map = d.maps.filter(ret)[0]
        self.assertEqual(mmap_map.permissions, "rwxp")

        d.terminate()

    def test_fork(self):
        d = debugger(RESOLVE_EXE("dummy_binary"), aslr=False)
        d.run()
        
        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        ip = d.instruction_pointer

        # Invoke the syscall
        ret = d.invoke_syscall("fork")

        self.assertEqual(d.regs.rip, ip)

        # Check the return value
        self.assertGreater(ret, 0)

        # Check that the child process is registered
        self.assertIsNotNone(d.children)

        d.children[0].terminate()
        d.terminate()

    def test_thread_spawn(self):
        d = debugger(RESOLVE_EXE("dummy_binary"), aslr=False)
        d.run()

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        # Allocate stack for the thread
        MAP_PRIVATE = 0x0000002
        MAP_ANON = 0x0000020

        PROT_READ = 0x1
        PROT_WRITE = 0x2

        new_stack = d.invoke_syscall("mmap", 0x13377000, 0x20000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0)
        new_tls = d.invoke_syscall("mmap",0xc0de0000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0)

        self.assertEqual(new_stack, 0x13377000)
        self.assertEqual(new_tls, 0xc0de0000)

        CLONE_VM = 0x00000100
        CLONE_THREAD = 0x00010000
        CLONE_FS = 0x00000200
        CLONE_SIGHAND = 0x00000800
        CLONE_FILES = 0x00000400

        flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD

        # Invoke the syscall
        ret = d.invoke_syscall("clone", flags, new_stack, d.regs.rsp + 0x100, d.regs.rsp + 0x108, new_tls)

        # Check the return value
        self.assertGreater(ret, 0)

        # Check that the child process is registered
        self.assertGreater(len(d.threads), 1)

        d.terminate()