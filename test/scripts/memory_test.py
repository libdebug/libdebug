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

        assert d.rip == bp.address

        address = d.rdi
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

        assert d.rip == bp.address

        address = d.rdi
        with libcontext.tmp(sym_lvl=5):
            arena = d.memory["main_arena", 256]

        def p64(x):
            return x.to_bytes(8, "little")

        self.assertTrue(p64(address - 0x10) in arena)

        d.kill()

    def test_memory_exceptions(self):
        d = self.d

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        try:
            print(d.memory[0x0, 256])
            self.assertTrue(False)
        except ValueError:
            self.assertTrue(False)
        except OSError:
            self.assertTrue(True)

        assert d.rip == bp.address

        address = d.rdi
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

            assert d.rip == bp.address

            address = d.rdi
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
        value = int.from_bytes(d.memory["state"], "little")
        self.assertEqual(value, 0xdeadbeef)
        self.assertEqual(d.rip, bp.address)

        d.kill()


if __name__ == "__main__":
    unittest.main()
