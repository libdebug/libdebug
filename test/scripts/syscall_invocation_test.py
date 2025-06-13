#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys
import uuid
import os
from unittest import TestCase, skipIf
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger

# Relative address of main in each binary
match PLATFORM:
    case "amd64":
        BP_ADDRESS = 0x1119
        READ_PATCH_CODE = b"\x48\xC7\xC0\x3C\x00\x00\x00\x48\xC7\xC7\x7B\x00\x00\x00\x0F\x05"
        MAP_BASE_1 = 0xdead0000
        MAP_BASE_2 = 0x13370000
        PROLOGUE_SIZE = 4
        SYSCALL_TO_HANDLE = "access"
    case "aarch64":
        BP_ADDRESS = 0x714
        READ_PATCH_CODE = b"\xa8\x0b\x80\xd2\x60\x0f\x80\xd2\x01\x00\x00\xd4"
        MAP_BASE_1 = 0xdead0000
        MAP_BASE_2 = 0x13370000
        PROLOGUE_SIZE = 4
        SYSCALL_TO_HANDLE = "faccessat"
    case "i386":
        BP_ADDRESS = 0x117d
        READ_PATCH_CODE = b"\xB8\x01\x00\x00\x00\xBB\x7B\x00\x00\x00\xCD\x80"
        MAP_BASE_1 = 0xb00000
        MAP_BASE_2 = 0x13370000
        PROLOGUE_SIZE = 3
        SYSCALL_TO_HANDLE = "access"
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
        errno = d.invoke_syscall("mprotect", code_map.start, code_map.size, PROT_READ | PROT_WRITE | PROT_EXEC)

        self.assertFalse(d.running)
        self.assertEqual(errno, 0)
        
        # Runtime patch (e.g. in AMD64...)
        # 0:  48 c7 c0 3c 00 00 00    mov    rax, 0x3c; exit syscall
        # 7:  48 c7 c7 7b 00 00 00    mov    rdi, 123 ; exit code
        # e:  0f 05                   syscall

        patch_code = READ_PATCH_CODE

        # First instruction of main on AMD64
        # <main>:	push   rbp
        # <main+1>:	mov    rbp,rsp
        # The syscall invocation will patch 2 bytes (0f 05) and restore them at the end
        # so we need to patch after the first instructions

        patch_offset = PROLOGUE_SIZE

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

        if PLATFORM == "aarch64":
            fd = d.invoke_syscall("openat", 0, stack.start, O_RDWR | O_CREAT, 0o666)
        elif PLATFORM == "i386" or PLATFORM == "amd64":
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
        if PLATFORM == "i386":
            # On i386, the mmap syscall has a different signature: it takes a struct instead of the arguments directly
            # struct mmap_arg_struct {
            #     unsigned long addr;
            #     unsigned long len;
            #     unsigned long prot;
            #     unsigned long flags;
            #     unsigned long fd;
            #     unsigned long off;
            # };
            p32 = lambda x: int.to_bytes(x, 4, "little")
    
            struct_bytes = \
                p32(MAP_BASE_1) + \
                p32(0x1000) + \
                p32(prot) + \
                p32(flags) + \
                p32(0xffffffff) + \
                p32(0)
            
            # We are goint to write the struct to a stack address
            stack = d.maps.filter("stack")[0]
            d.memory[stack.start, len(struct_bytes), "absolute"] = struct_bytes

            # Invoke the syscall
            ret = d.invoke_syscall("mmap", stack.start)
        else:
            # unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off
            ret = d.invoke_syscall("mmap", MAP_BASE_1, 0x1000, prot, flags, -1, 0)

        # Page aligned address should be returned
        self.assertEqual(ret, MAP_BASE_1)

        post_num_maps = len(d.maps)
        self.assertGreater(post_num_maps, prev_num_maps)

        # Check protection
        mmap_map = d.maps.filter(ret)[0]
        self.assertEqual(mmap_map.permissions, "rwxp")

        d.terminate()
    
    @skipIf(PLATFORM == "aarch64", "Fork not supported on aarch64")
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

        self.assertEqual(d.instruction_pointer, ip)

        # Check the return value
        self.assertGreater(ret, 0)

        # Check that the child process is registered
        self.assertIsNotNone(d.children)

        d.children[0].terminate()
        d.terminate()

    def test_clone_process(self):
        d = debugger(RESOLVE_EXE("dummy_binary"), aslr=False)
        d.run()
        
        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        ip = d.instruction_pointer

        # Invoke the syscall
        SIGCHLD = 17

        # unsigned long clone_flags, unsigned long newsp, int *parent_tidptr, unsigned long tls, int *child_tidptr
        clone_flags = SIGCHLD
        stack_base = d.maps.filter("stack")[0].start

        if PLATFORM == "amd64":
            ret = d.invoke_syscall("clone", clone_flags, stack_base, stack_base + 0x08, stack_base + 0x10, d.regs.fs_base)
        # For some obscure reason, the last two arguments are swapped in many architectures
        elif PLATFORM == "i386":
            ret = d.invoke_syscall("clone", clone_flags, stack_base, stack_base + 0x04, d.regs.gs, stack_base + 0x08)
        elif PLATFORM == "aarch64":
            # To retrieve the TLS base, we need to use the TPIDR_EL0 register
            # mrs x0, TPIDR_EL0
            code_patch = b"\x40\xd0\x3b\xd5"
            original_code = d.memory[d.instruction_pointer:d.instruction_pointer + len(code_patch), "absolute"]

            old_x0 = d.regs.x0

            d.instruction_pointer -= 4
            d.memory[d.instruction_pointer:d.instruction_pointer + len(code_patch), "absolute"] = code_patch
            # Execute the instruction
            d.step()
            tls = d.regs.x0

            # Restore the original code and register
            d.memory[d.instruction_pointer-4:d.instruction_pointer, "absolute"] = original_code
            d.regs.x0 = old_x0

            ret = d.invoke_syscall("clone", clone_flags, stack_base, stack_base + 0x08, tls, stack_base + 0x10)        

        self.assertEqual(d.instruction_pointer, ip)

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

        prot = PROT_READ | PROT_WRITE
        flags = MAP_PRIVATE | MAP_ANON

        if PLATFORM == "i386":
            p32 = lambda x: int.to_bytes(x, 4, "little")

            # First page to mmap, new stack
            struct_bytes = \
                p32(MAP_BASE_1) + \
                p32(0x20000) + \
                p32(prot) + \
                p32(flags) + \
                p32(0xffffffff) + \
                p32(0)
            
            # We are goint to write the struct to a stack address
            stack = d.maps.filter("stack")[0]
            d.memory[stack.start, len(struct_bytes), "absolute"] = struct_bytes

            # Invoke the syscall
            new_stack = d.invoke_syscall("mmap", stack.start)

            # Second page to mmap, new TLS
            struct_bytes = \
                p32(MAP_BASE_2) + \
                p32(0x1000) + \
                p32(prot) + \
                p32(flags) + \
                p32(0xffffffff) + \
                p32(0)
            
            # We are goint to write the struct to a stack address
            stack = d.maps.filter("stack")[0]
            d.memory[stack.start, len(struct_bytes), "absolute"] = struct_bytes

            # Invoke the syscall
            new_tls = d.invoke_syscall("mmap", stack.start)
        else:
            new_stack = d.invoke_syscall("mmap", MAP_BASE_1, 0x20000, prot, flags, -1, 0)
            new_tls = d.invoke_syscall("mmap",MAP_BASE_2, 0x1000, prot, flags, -1, 0)

        self.assertEqual(new_stack, MAP_BASE_1)
        self.assertEqual(new_tls, MAP_BASE_2)

        CLONE_VM = 0x00000100
        CLONE_THREAD = 0x00010000
        CLONE_FS = 0x00000200
        CLONE_SIGHAND = 0x00000800
        CLONE_FILES = 0x00000400

        flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD

        if PLATFORM == "amd64":
            stack_pointer = d.regs.rsp
        elif PLATFORM == "i386":
            stack_pointer = d.regs.esp
        elif PLATFORM == "aarch64":
            stack_pointer = d.regs.sp

        # Invoke the syscall
        if PLATFORM == "amd64":
            ret = d.invoke_syscall("clone", flags, new_stack, stack_pointer + 0x100, stack_pointer + 0x108, new_tls)
        # For some obscure reason, the last two arguments are swapped in many architectures
        elif PLATFORM == "i386" or PLATFORM == "aarch64":
            ret = d.invoke_syscall("clone", flags, new_stack, stack_pointer + 0x100, new_tls, stack_pointer + 0x108)  

        # Check the return value
        self.assertGreater(ret, 0)

        # Check that the child process is registered
        self.assertGreater(len(d.threads), 1)

        d.terminate()

    def test_invocation_in_callback(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        pipe = d.run()

        def main_callback(t, bp):
            # Retrieve binary map
            binary_map = d.maps.filter("binary")[0]

            # Invoke the syscall
            ret = d.invoke_syscall("write", 1, binary_map.start, 0x10)

            # Check the return value
            self.assertEqual(ret, 0x10)

        # Set a breakpoint to <main>
        d.breakpoint(BP_ADDRESS, hardware=True, callback=main_callback, file="binary")

        d.cont()
        out = pipe.recv(4)
        d.wait()

        # Check the output
        self.assertIn(b"\x7fELF", out)

        d.terminate()

    def test_invocation_callback_exception(self):
        d = debugger(RESOLVE_EXE("dummy_binary"))
        d.run()

        def sys_callback(t, h):
            binary_map = d.maps.filter("binary")[0]
            
            with self.assertRaises(RuntimeError):
                d.invoke_syscall("write", 1, binary_map.start, 0x10)

        d.breakpoint(BP_ADDRESS, hardware=True, file="binary")

        d.cont()
        d.wait()

        d.handle_syscall("write", on_enter=sys_callback)

        d.cont()
        d.wait()

        d.terminate()

    def test_invocation_in_syscall_enter(self):
        d = debugger(RESOLVE_EXE("dummy_binary"), continue_to_binary_entrypoint=False)

        d.run()

        d.handle_syscall(SYSCALL_TO_HANDLE)

        d.cont()
        d.wait()

        # Now we are stopped at the start of the syscall get_random
        # Let's see if we are able to invoke a syscall here
        binary_map = d.maps.filter("binary")[0]
        
        with self.assertRaises(RuntimeError):
            d.invoke_syscall("write", 1, binary_map.start, 0x10)

        d.terminate()