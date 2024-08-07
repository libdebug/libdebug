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
        
        bp1 = d.bp(0xb10, file="binary")
        bp2 = d.bp(0xb44, file="binary")
        
        d.cont()

        assert bp1.hit_on(d)

        baseval = int.from_bytes(bytes(list(range(16))), sys.byteorder)

        for i in range(16):
            assert hasattr(d.regs, f"q{i}")
            assert getattr(d.regs, f"q{i}") == baseval
            assert getattr(d.regs, f"v{i}") == baseval
            assert getattr(d.regs, f"d{i}") == baseval & 0xFFFFFFFFFFFFFFFF
            assert getattr(d.regs, f"s{i}") == baseval & 0xFFFFFFFF
            assert getattr(d.regs, f"h{i}") == baseval & 0xFFFF
            assert getattr(d.regs, f"b{i}") == baseval & 0xFF
            baseval = (baseval >> 8) + ((baseval & 255) << 120)

        baseval = int.from_bytes(bytes(list(range(128, 128 + 16, 1))), sys.byteorder)

        for i in range(16, 32, 1):
            assert hasattr(d.regs, f"q{i}")
            assert getattr(d.regs, f"q{i}") == baseval
            assert getattr(d.regs, f"v{i}") == baseval
            assert getattr(d.regs, f"d{i}") == baseval & 0xFFFFFFFFFFFFFFFF
            assert getattr(d.regs, f"s{i}") == baseval & 0xFFFFFFFF
            assert getattr(d.regs, f"h{i}") == baseval & 0xFFFF
            assert getattr(d.regs, f"b{i}") == baseval & 0xFF
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
