#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest
from pathlib import Path

from libdebug import debugger


class FloatingPointTest(unittest.TestCase):
    def test_floating_point_reg_access(self):
        # This test is divided into two parts, depending on the current hardware

        # Let's check if we have AVX512
        with Path("/proc/cpuinfo").open() as f:
            cpuinfo = f.read()
            if "avx512" in cpuinfo:
                # Run an AVX512 test
                self.test_floating_point_reg_access_avx512()
                self.test_floating_point_reg_access_avx()
                self.test_floating_point_reg_access_generic()
            elif "avx" in cpuinfo:
                # Run an AVX test
                self.test_floating_point_reg_access_avx()
                self.test_floating_point_reg_access_generic()
            else:
                # Run a generic test
                self.test_floating_point_reg_access_generic()

    def test_floating_point_reg_access_avx512(self):
        pass

    def test_floating_point_reg_access_avx(self):
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
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm1, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm2, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm3, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm4, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm5, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm6, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm7, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm8, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm9, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm10, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm11, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm12, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm13, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm14, baseval)
        baseval = (baseval >> 8) + ((baseval & 255) << 248)
        self.assertEqual(d.regs.ymm15, baseval)

        d.kill()

    def test_floating_point_reg_access_generic(self):
        pass
