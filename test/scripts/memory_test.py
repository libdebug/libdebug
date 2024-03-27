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
        d.wait()

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
        d.wait()

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
        except RuntimeError:
            self.assertTrue(True)
            pass

        d.wait()

        assert d.rip == bp.address

        address = d.rdi
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)

        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)

        d.kill()


if __name__ == "__main__":
    unittest.main()
