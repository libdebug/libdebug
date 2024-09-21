#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest
from pwn import process

from libdebug import debugger, libcontext


class MemoryFastTest(unittest.TestCase):
    def test_memory(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        assert d.regs.rip == bp.address

        address = d.regs.rdi
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)

        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)

        d.kill()
        d.terminate()

    def test_mem_access_libs(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        d.run()

        bp = d.breakpoint("leak_address")

        d.cont()

        assert d.regs.rip == bp.address

        address = d.regs.rdi
        with libcontext.tmp(sym_lvl=5):
            arena = d.memory["main_arena", 256, "libc"]

        def p64(x):
            return x.to_bytes(8, "little")

        self.assertTrue(p64(address - 0x10) in arena)

        d.kill()
        d.terminate()

    def test_memory_exceptions(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        # This should not raise an exception
        file = d.memory[0x0, 256]

        # File should start with ELF magic number
        self.assertTrue(file.startswith(b"\x7fELF"))

        assert d.regs.rip == bp.address

        address = d.regs.rdi
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)

        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)

        d.kill()
        d.terminate()

    def test_memory_multiple_runs(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        for _ in range(10):
            d.run()

            bp = d.breakpoint("change_memory")

            d.cont()

            assert d.regs.rip == bp.address

            address = d.regs.rdi
            prev = bytes(range(256))

            self.assertTrue(d.memory[address, 256] == prev)

            d.memory[address + 128 :] = b"abcd123456"
            prev = prev[:128] + b"abcd123456" + prev[138:]

            self.assertTrue(d.memory[address : address + 256] == prev)

            d.kill()

        d.terminate()

    def test_memory_access_while_running(self):
        d = debugger("binaries/memory_test_2", fast_memory=True)

        d.run()

        bp = d.breakpoint("do_nothing")

        d.cont()

        # Verify that memory access is only possible when the process is stopped
        value = int.from_bytes(d.memory["state", 8], "little")
        self.assertEqual(value, 0xDEADBEEF)
        self.assertEqual(d.regs.rip, bp.address)

        d.kill()
        d.terminate()

    def test_memory_access_methods(self):
        d = debugger("binaries/memory_test_2", fast_memory=True)

        d.run()

        base = d.regs.rip & 0xFFFFFFFFFFFFF000 - 0x1000

        # Test different ways to access memory at the start of the file
        file_0 = d.memory[base, 256]
        file_1 = d.memory[0x0, 256]
        file_2 = d.memory[0x0:0x100]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_0, file_2)

        # Validate that the length of the read bytes is correct
        file_0 = d.memory[0x0]
        file_1 = d.memory[base]

        self.assertEqual(file_0, file_1)
        self.assertEqual(len(file_0), 1)

        # Validate that slices work correctly
        file_0 = d.memory[0x0:"do_nothing"]
        file_1 = d.memory[base:"do_nothing"]

        self.assertEqual(file_0, file_1)

        self.assertRaises(ValueError, lambda: d.memory[0x1000:0x0])
        # _fini is after main
        self.assertRaises(ValueError, lambda: d.memory["_fini":"main"])

        # Test different ways to write memory
        d.memory[0x0, 8] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8], b"abcd1234")

        d.memory[0x0, 8] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[base:] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.memory[base:] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.memory[base] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8], b"abcd1234")

        d.memory[0x0, 8] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.memory["main":] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.memory["main"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.kill()
        d.terminate()

    def test_memory_access_methods_backing_file(self):
        d = debugger("binaries/memory_test_2", fast_memory=True)

        d.run()

        base = d.regs.rip & 0xFFFFFFFFFFFFF000 - 0x1000

        # Validate that slices work correctly
        file_0 = d.memory[0x0:"do_nothing", "binary"]
        file_1 = d.memory[0x0:"do_nothing", "memory_test_2"]
        file_2 = d.memory[base:"do_nothing", "binary"]
        file_3 = d.memory[base:"do_nothing", "memory_test_2"]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_1, file_2)
        self.assertEqual(file_2, file_3)

        # Test different ways to write memory
        d.memory[0x0, 8, "binary"] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0, 8, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8, "binary"] = b"abcd1234"
        self.assertEqual(d.memory[0x0:8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory[0x0:8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":, "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory["main":, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory["main":, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main", "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main", "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "hybrid"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "hybrid"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(ValueError):
            d.memory["main":"main+8", "absolute"] = b"abcd1234"

        d.kill()
        d.terminate()

    def test_memory_large_read(self):
        d = debugger("binaries/memory_test_3", fast_memory=True)

        d.run()

        bp = d.bp("do_nothing")

        d.cont()

        assert bp.hit_on(d)

        leak = d.regs.rdi

        # Read 4MB of memory
        data = d.memory[leak, 4 * 1024 * 1024]

        assert data == b"".join(x.to_bytes(4, "little") for x in range(1024 * 1024))

        d.kill()
        d.terminate()

    def test_invalid_memory_location(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        d.run()

        bp = d.bp("change_memory")

        d.cont()

        assert d.regs.rip == bp.address

        address = 0xDEADBEEFD00D

        with self.assertRaises(ValueError):
            d.memory[address, 256, "absolute"]

        d.kill()
        d.terminate()

    def test_memory_multiple_threads(self):
        d = debugger("binaries/memory_test_4", fast_memory=True)

        d.run()

        leaks = []
        leak_addresses = []

        def leak(t, _):
            leaks.append(t.memory[t.regs.rdi, 16])
            leak_addresses.append(t.regs.rdi)

        d.bp("leak", callback=leak, hardware=True)
        exit = d.bp("before_exit", hardware=True)

        d.cont()
        d.wait()

        assert exit.hit_on(d)

        for i in range(8):
            assert (chr(i).encode("latin-1") * 16) in leaks

        leaks = [d.memory[x, 16] for x in leak_addresses]

        # threads are stopped, check we correctly read the memory
        for i in range(8):
            assert (chr(i).encode("latin-1") * 16) in leaks

        d.kill()
        d.terminate()

    def test_memory_mixed_access(self):
        d = debugger("binaries/memory_test_2", fast_memory=True)

        d.run()

        base = d.regs.rip & 0xFFFFFFFFFFFFF000 - 0x1000

        # Test different ways to access memory at the start of the file
        file_0 = d.memory[base, 256]
        d.fast_memory = False
        file_1 = d.memory[0x0, 256]
        d.fast_memory = True
        file_2 = d.memory[0x0:0x100]
        d.fast_memory = False
        file_3 = d.memory[0x0:0x100]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_0, file_2)
        self.assertEqual(file_0, file_3)

        for _ in range(3):
            d.step()

        d.fast_memory = False
        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.fast_memory = True
        self.assertEqual(d.memory[base, 8], b"abcd1234")
        d.memory[base] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.assertEqual(d.memory[base, 8], b"\x01\x02\x03\x04\x05\x06\x07\x08")

        d.fast_memory = False
        self.assertEqual(d.memory[base, 8], b"\x01\x02\x03\x04\x05\x06\x07\x08")
        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.kill()
        d.terminate()

    def test_memory_attach(self):
        # Ensure that fast-memory works when attaching to a process
        r = process("binaries/attach_test")

        d = debugger(fast_memory=True)

        d.attach(r.pid)

        self.assertEqual(d.memory[0x0, 4, "binary"], b"\x7fELF")

        d.kill()
        d.terminate()

    def test_search_memory(self):
        d = debugger("binaries/memory_test", fast_memory=True)

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        assert d.regs.rip == bp.address

        address = d.regs.rdi
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)
        
        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)
        
        start = d.search_maps("heap")[0].start
        end = d.search_maps("heap")[-1].end - 1
        
        # Search for the string "abcd123456" in the whole memory
        self.assertTrue(d.memory.find(b"abcd123456") == [address + 128])
        
        # Search for the string "abcd123456" in the memory starting from start
        self.assertTrue(d.memory.find(b"abcd123456", start=start) == [address + 128])
        
        # Search for the string "abcd123456" in the memory ending at end
        self.assertTrue(d.memory.find(b"abcd123456", end=end) == [address + 128])
        
        # Search for the string "abcd123456" in the heap using backing file
        self.assertTrue(d.memory.find(b"abcd123456", file="heap") == [address + 128])
        
        # Search for the string "abcd123456" in the heap using start and end
        self.assertTrue(d.memory.find(b"abcd123456", start=start, end=end) == [address + 128])

        d.kill()
        d.terminate()