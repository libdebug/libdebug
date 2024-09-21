#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest
from pathlib import Path
from random import randint

from libdebug import debugger


class FloatingPointTest(unittest.TestCase):
    def test_floating_point_reg_access(self):
        # This test is divided into two parts, depending on the current hardware

        # Let's check if we have AVX512
        with Path("/proc/cpuinfo").open() as f:
            cpuinfo = f.read()

        if "avx512" in cpuinfo:
            # Run an AVX512 test
            self.avx512()
            self.avx()
            self.mmx()
        elif "avx" in cpuinfo:
            # Run an AVX test
            self.avx()
            self.mmx()
        else:
            # Run a generic test
            self.mmx()

    def avx512(self):
        d = debugger("binaries/floating_point_2696_test")

        d.run()

        bp1 = d.bp(0x40143E)
        bp2 = d.bp(0x401467)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "xmm31"))
        self.assertTrue(hasattr(d.regs, "ymm0"))
        self.assertTrue(hasattr(d.regs, "ymm31"))
        self.assertTrue(hasattr(d.regs, "zmm0"))
        self.assertTrue(hasattr(d.regs, "zmm31"))

        baseval = int.from_bytes(bytes(list(range(64))), "little")

        for i in range(32):
            self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval & ((1 << 128) - 1))
            self.assertEqual(getattr(d.regs, f"ymm{i}"), baseval & ((1 << 256) - 1))
            self.assertEqual(getattr(d.regs, f"zmm{i}"), baseval)
            baseval = (baseval >> 8) + ((baseval & 255) << 504)

        d.regs.zmm0 = 0xDEADBEEFDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(32):
            val = randint(0, 2**512 - 1)
            setattr(d.regs, f"zmm{i}", val)
            self.assertEqual(getattr(d.regs, f"zmm{i}"), val)

        d.kill()

    def avx(self):
        d = debugger("binaries/floating_point_896_test")

        d.run()

        bp1 = d.bp(0x40159E)
        bp2 = d.bp(0x4015C5)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "ymm0"))
        self.assertTrue(hasattr(d.regs, "xmm15"))
        self.assertTrue(hasattr(d.regs, "ymm15"))

        baseval = int.from_bytes(bytes(list(range(0, 256, 17)) + list(range(16))), "little")

        self.assertEqual(d.regs.ymm0, baseval)
        self.assertEqual(d.regs.xmm0, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm1, baseval)
        self.assertEqual(d.regs.xmm1, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm2, baseval)
        self.assertEqual(d.regs.xmm2, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm3, baseval)
        self.assertEqual(d.regs.xmm3, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm4, baseval)
        self.assertEqual(d.regs.xmm4, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm5, baseval)
        self.assertEqual(d.regs.xmm5, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm6, baseval)
        self.assertEqual(d.regs.xmm6, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm7, baseval)
        self.assertEqual(d.regs.xmm7, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm8, baseval)
        self.assertEqual(d.regs.xmm8, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm9, baseval)
        self.assertEqual(d.regs.xmm9, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm10, baseval)
        self.assertEqual(d.regs.xmm10, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm11, baseval)
        self.assertEqual(d.regs.xmm11, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm12, baseval)
        self.assertEqual(d.regs.xmm12, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm13, baseval)
        self.assertEqual(d.regs.xmm13, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm14, baseval)
        self.assertEqual(d.regs.xmm14, baseval & ((1 << 128) - 1))
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm15, baseval)
        self.assertEqual(d.regs.xmm15, baseval & ((1 << 128) - 1))

        d.regs.ymm0 = 0xDEADBEEFDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(16):
            val = randint(0, 2**256 - 1)
            setattr(d.regs, f"ymm{i}", val)
            self.assertEqual(getattr(d.regs, f"xmm{i}"), val & ((1 << 128) - 1))
            self.assertEqual(getattr(d.regs, f"ymm{i}"), val)

        # validate that register states are correctly flushed and then restored
        values = []

        for i in range(16):
            val = randint(0, 2**256 - 1)
            setattr(d.regs, f"ymm{i}", val)
            values.append(val)

        d.step()

        for i in range(16):
            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        d.regs.ymm7 = 0xDEADBEEFDEADBEEF

        for i in range(16):
            if i == 7:
                continue

            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        d.step()

        for i in range(16):
            if i == 7:
                continue

            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        self.assertEqual(d.regs.ymm7, 0xDEADBEEFDEADBEEF)

        d.kill()

        def callback(t, _):
            baseval = int.from_bytes(bytes(list(range(0, 256, 17)) + list(range(16))), "little")
            for i in range(16):
                self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval & ((1 << 128) - 1))
                self.assertEqual(getattr(d.regs, f"ymm{i}"), baseval)
                baseval = (baseval >> 8) + ((baseval & 255) << 248)

            t.regs.ymm0 = 0xDEADBEEFDEADBEEF

        d.run()

        d.bp(0x40159E, callback=callback)
        bp = d.bp(0x4015C5)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.kill()

    def mmx(self):
        d = debugger("binaries/floating_point_512_test")

        d.run()

        bp1 = d.bp(0x401372)
        bp2 = d.bp(0x401399)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "xmm15"))

        baseval = int.from_bytes(bytes(list(range(0, 256, 17))), "little")
        self.assertEqual(d.regs.xmm0, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm1, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm2, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm3, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm4, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm5, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm6, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm7, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm8, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm9, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm10, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm11, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm12, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm13, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm14, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 120)
        self.assertEqual(d.regs.xmm15, baseval)

        d.regs.xmm0 = 0xDEADBEEFDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(16):
            val = randint(0, 2**128 - 1)
            setattr(d.regs, f"xmm{i}", val)
            self.assertEqual(getattr(d.regs, f"xmm{i}"), val)

        d.kill()

        def callback(t, _):
            baseval = int.from_bytes(bytes(list(range(0, 256, 17))), "little")
            for i in range(16):
                self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval)
                baseval = (baseval >> 8) + ((baseval & 255) << 120)

            t.regs.xmm0 = 0xDEADBEEFDEADBEEF

        d.run()

        d.bp(0x401372, callback=callback)
        bp = d.bp(0x401399)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.kill()
