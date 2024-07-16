#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
import unittest
from random import randint

from libdebug import debugger


class FloatingPointTest(unittest.TestCase):
    def test_floating_point_reg_access(self):
        d = debugger("binaries/floating_point_test")
        
        d.run()
        
        bp1 = d.bp(0x810, file="binary")
        bp2 = d.bp(0x844, file="binary")
        
        d.cont()

        assert bp1.hit_on(d)

        baseval = int.from_bytes(bytes(list(range(16))), sys.byteorder)

        for i in range(32):
            assert hasattr(d.regs, f"q{i}")
            assert getattr(d.regs, f"q{i}") == baseval
            assert getattr(d.regs, f"v{i}") == baseval
            assert getattr(d.regs, f"d{i}") == baseval & ((1 << 64) - 1)
            assert getattr(d.regs, f"s{i}") == baseval & ((1 << 32) - 1)
            assert getattr(d.regs, f"h{i}") == baseval & ((1 << 16) - 1)
            assert getattr(d.regs, f"b{i}") == baseval & ((1 << 8) - 1)
            baseval = (baseval >> 8) + ((baseval & 255) << 120)

        for i in range(32):
            val = randint(0, (1 << 128) - 1)
            setattr(d.regs, f"q{i}", val)
            assert getattr(d.regs, f"q{i}") == val
            assert getattr(d.regs, f"v{i}") == val

        for i in range(32):
            val = randint(0, (1 << 64) - 1)
            setattr(d.regs, f"d{i}", val)
            assert getattr(d.regs, f"d{i}") == val

        for i in range(32):
            val = randint(0, (1 << 32) - 1)
            setattr(d.regs, f"s{i}", val)
            assert getattr(d.regs, f"s{i}") == val

        for i in range(32):
            val = randint(0, (1 << 16) - 1)
            setattr(d.regs, f"h{i}", val)
            assert getattr(d.regs, f"h{i}") == val

        for i in range(32):
            val = randint(0, (1 << 8) - 1)
            setattr(d.regs, f"b{i}", val)
            assert getattr(d.regs, f"b{i}") == val

        d.regs.q0 = 0xdeadbeefdeadbeef

        d.cont()

        assert bp2.hit_on(d)

        d.kill()
        d.terminate()