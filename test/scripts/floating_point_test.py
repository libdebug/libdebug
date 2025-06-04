#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import sys
from pathlib import Path
from random import randint
from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


class FloatingPointTest(TestCase):
    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_floating_point_reg_access_amd64(self):
        # This test is divided into two parts, depending on the current hardware

        # Let's check if we have AVX512
        with Path("/proc/cpuinfo").open() as f:
            cpuinfo = f.read()

        if "avx512" in cpuinfo:
            # Run an AVX512 test
            self.amd64_avx512()
            self.amd64_avx()
            self.amd64_xmm()
            self.amd64_mmx()
            self.amd64_st()
        elif "avx" in cpuinfo:
            # Run an AVX test
            self.amd64_avx()
            self.amd64_xmm()
            self.amd64_mmx()
            self.amd64_st()
        else:
            # Run a generic test
            self.amd64_xmm()
            self.amd64_mmx()
            self.amd64_st()

    def amd64_avx512(self):
        d = debugger(RESOLVE_EXE("floating_point_avx512_test"))

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
        d.terminate()

    def amd64_avx(self):
        d = debugger(RESOLVE_EXE("floating_point_avx2_test"))

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
        d.terminate()

    def amd64_xmm(self):
        d = debugger(RESOLVE_EXE("floating_point_sse_test"))

        d.run()

        bp1 = d.bp(0x4006ba)
        bp2 = d.bp(0x4006e1)

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

        d.bp(0x4006ba, callback=callback)
        bp = d.bp(0x4006e1)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.kill()
        d.terminate()

    def amd64_mmx(self):
        d = debugger(RESOLVE_EXE("floating_point_mmx_test"))

        d.run()

        bp1 = d.bp(0x40119e)
        bp2 = d.bp(0x4011be)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "mm0"))
        self.assertTrue(hasattr(d.regs, "mm7"))

        for i in range(8):
            baseval = int.from_bytes(bytes(list(range(17 * i, 128 + 17 * i, 17))), "little")
            self.assertEqual(getattr(d.regs, f"mm{i}"), baseval)

        d.regs.mm0 = 0xDEADBEEFDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**64 - 1)
            setattr(d.regs, f"mm{i}", val)
            self.assertEqual(getattr(d.regs, f"mm{i}"), val)

        d.kill()
        d.terminate()

    def amd64_st(self):
        d = debugger(RESOLVE_EXE("floating_point_mmx_test"))

        d.run()

        bp1 = d.bp(0x40124e)
        bp2 = d.bp(0x401271)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "st0"))
        self.assertTrue(hasattr(d.regs, "st7"))

        self.assertAlmostEqual(d.regs.st0, 890.123)
        self.assertAlmostEqual(d.regs.st1, 789.012)
        self.assertAlmostEqual(d.regs.st2, 678.901)
        self.assertAlmostEqual(d.regs.st3, 567.890)
        self.assertAlmostEqual(d.regs.st4, 456.789)
        self.assertAlmostEqual(d.regs.st5, 345.678)
        self.assertAlmostEqual(d.regs.st6, 234.567)
        self.assertAlmostEqual(d.regs.st7, 123.456)

        d.regs.st0 = 1337.1337

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**64 - 1)
            setattr(d.regs, f"st{i}", val)
            self.assertAlmostEqual(getattr(d.regs, f"st{i}"), val)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_floating_point_reg_access_aarch64(self):
        d = debugger(RESOLVE_EXE("floating_point_test"))
        
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

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_floating_point_reg_access_i386(self):
        # This test is divided into two parts, depending on the current hardware

        # Let's check if we have AVX512
        with Path("/proc/cpuinfo").open() as f:
            cpuinfo = f.read()

        if "avx512" in cpuinfo:
            # Run an AVX512 test
            self.i386_avx512()
            self.i386_avx()
            self.i386_xmm()
            self.i386_mmx()
            self.i386_st()
        elif "avx" in cpuinfo:
            # Run an AVX test
            self.i386_avx()
            self.i386_xmm()
            self.i386_mmx()
            self.i386_st()
        else:
            # Run a generic test
            self.i386_xmm()
            self.i386_mmx()
            self.i386_st()

    def i386_avx512(self):
        d = debugger(RESOLVE_EXE("floating_point_avx512_test"))

        d.run()

        bp1 = d.bp(0x804926e)
        bp2 = d.bp(0x804928d)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "xmm7"))
        self.assertTrue(hasattr(d.regs, "ymm0"))
        self.assertTrue(hasattr(d.regs, "ymm7"))
        self.assertTrue(hasattr(d.regs, "zmm0"))
        self.assertTrue(hasattr(d.regs, "zmm7"))

        baseval = int.from_bytes(bytes(list(range(64))), "little")

        for i in range(8):
            self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval & ((1 << 128) - 1))
            self.assertEqual(getattr(d.regs, f"ymm{i}"), baseval & ((1 << 256) - 1))
            self.assertEqual(getattr(d.regs, f"zmm{i}"), baseval)
            baseval = (baseval >> 8) + ((baseval & 255) << 504)

        d.regs.zmm0 = 0xdeadbeef

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**512 - 1)
            setattr(d.regs, f"zmm{i}", val)
            self.assertEqual(getattr(d.regs, f"zmm{i}"), val)

        d.kill()
        d.terminate()

    def i386_avx(self):
        d = debugger(RESOLVE_EXE("floating_point_avx2_test"))

        d.run()

        bp1 = d.bp(0x80493b9)
        bp2 = d.bp(0x80493d6)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "ymm0"))
        self.assertTrue(hasattr(d.regs, "xmm7"))
        self.assertTrue(hasattr(d.regs, "ymm7"))

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

        d.regs.ymm0 = 0xDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**256 - 1)
            setattr(d.regs, f"ymm{i}", val)
            self.assertEqual(getattr(d.regs, f"xmm{i}"), val & ((1 << 128) - 1))
            self.assertEqual(getattr(d.regs, f"ymm{i}"), val)

        # validate that register states are correctly flushed and then restored
        values = []

        for i in range(8):
            val = randint(0, 2**256 - 1)
            setattr(d.regs, f"ymm{i}", val)
            values.append(val)

        d.step()

        for i in range(8):
            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        d.regs.ymm7 = 0xDEADBEEF

        for i in range(8):
            if i == 7:
                continue

            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        d.step()

        for i in range(8):
            if i == 7:
                continue

            self.assertEqual(getattr(d.regs, f"ymm{i}"), values[i])

        self.assertEqual(d.regs.ymm7, 0xDEADBEEF)

        d.kill()

        def callback(t, _):
            baseval = int.from_bytes(bytes(list(range(0, 256, 17)) + list(range(16))), "little")
            for i in range(8):
                self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval & ((1 << 128) - 1))
                self.assertEqual(getattr(d.regs, f"ymm{i}"), baseval)
                baseval = (baseval >> 8) + ((baseval & 255) << 248)

            t.regs.ymm0 = 0xDEADBEEF

        d.run()

        d.bp(0x80493b9, callback=callback)
        bp = d.bp(0x80493d6)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.kill()
        d.terminate()

    def i386_xmm(self):
        d = debugger(RESOLVE_EXE("floating_point_sse_test"))

        d.run()

        bp1 = d.bp(0x804926d)
        bp2 = d.bp(0x804928a)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "xmm0"))
        self.assertTrue(hasattr(d.regs, "xmm7"))

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

        d.regs.xmm0 = 0xDEADBEEF

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**128 - 1)
            setattr(d.regs, f"xmm{i}", val)
            self.assertEqual(getattr(d.regs, f"xmm{i}"), val)

        d.kill()

        def callback(t, _):
            baseval = int.from_bytes(bytes(list(range(0, 256, 17))), "little")
            for i in range(8):
                self.assertEqual(getattr(d.regs, f"xmm{i}"), baseval)
                baseval = (baseval >> 8) + ((baseval & 255) << 120)

            t.regs.xmm0 = 0xdeadbeef

        d.run()

        d.bp(0x804926d, callback=callback)
        bp = d.bp(0x804928a)

        d.cont()

        self.assertTrue(bp.hit_on(d))

        d.kill()
        d.terminate()

    def i386_mmx(self):
        d = debugger(RESOLVE_EXE("floating_point_mmx_test"))

        d.run()

        bp1 = d.bp(0x8049231)
        bp2 = d.bp(0x8049251)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "mm0"))
        self.assertTrue(hasattr(d.regs, "mm7"))

        for i in range(8):
            baseval = int.from_bytes(bytes(list(range(17 * i, 128 + 17 * i, 17))), "little")
            self.assertEqual(getattr(d.regs, f"mm{i}"), baseval)

        d.regs.mm0 = 0xdeadbeef

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**64 - 1)
            setattr(d.regs, f"mm{i}", val)
            self.assertEqual(getattr(d.regs, f"mm{i}"), val)

        d.kill()
        d.terminate()

    def i386_st(self):
        d = debugger(RESOLVE_EXE("floating_point_mmx_test"))

        d.run()

        bp1 = d.bp(0x80492c5)
        bp2 = d.bp(0x80492f4)

        d.cont()

        self.assertTrue(bp1.hit_on(d))

        self.assertTrue(hasattr(d.regs, "st0"))
        self.assertTrue(hasattr(d.regs, "st7"))

        self.assertAlmostEqual(d.regs.st0, 890.123)
        self.assertAlmostEqual(d.regs.st1, 789.012)
        self.assertAlmostEqual(d.regs.st2, 678.901)
        self.assertAlmostEqual(d.regs.st3, 567.890)
        self.assertAlmostEqual(d.regs.st4, 456.789)
        self.assertAlmostEqual(d.regs.st5, 345.678)
        self.assertAlmostEqual(d.regs.st6, 234.567)
        self.assertAlmostEqual(d.regs.st7, 123.456)

        d.regs.st0 = 1337.1337

        d.cont()

        self.assertTrue(bp2.hit_on(d))

        for i in range(8):
            val = randint(0, 2**64 - 1)
            setattr(d.regs, f"st{i}", val)
            self.assertAlmostEqual(getattr(d.regs, f"st{i}"), val)

        d.kill()
        d.terminate()
