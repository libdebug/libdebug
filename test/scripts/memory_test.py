#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger, libcontext


class MemoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.d = debugger("binaries/memory_test")

    def test_memory(self):
        d = self.d

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

    def test_mem_access_libs(self):
        d = self.d

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

    def test_memory_exceptions(self):
        d = self.d

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

    def test_memory_multiple_runs(self):
        d = self.d

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

    def test_memory_access_while_running(self):
        d = debugger("binaries/memory_test_2")

        d.run()

        bp = d.breakpoint("do_nothing")

        d.cont()

        # Verify that memory access is only possible when the process is stopped
        value = int.from_bytes(d.memory["state", 8], "little")
        self.assertEqual(value, 0xDEADBEEF)
        self.assertEqual(d.regs.rip, bp.address)

        d.kill()

    def test_memory_access_methods(self):
        d = debugger("binaries/memory_test_2")

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

    def test_memory_access_methods_backing_file(self):
        d = debugger("binaries/memory_test_2")

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

        d.memory["main":"main+8", "default"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "default"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(ValueError):
            d.memory["main":"main+8", "absolute"] = b"abcd1234"

        d.kill()


if __name__ == "__main__":
    unittest.main()
