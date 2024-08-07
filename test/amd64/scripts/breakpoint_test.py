#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import unittest

from libdebug import debugger


class BreakpointTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/breakpoint_test")

        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def test_bps(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 10)

        self.d.kill()

    def test_bp_disable(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 1)

        self.d.kill()

    def test_bp_disable_hw(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B, hardware=True)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 1)

    def test_bp_disable_reenable(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp4 = d.breakpoint(0x401162)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        self.d.kill()

    def test_bp_disable_reenable_hw(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp4 = d.breakpoint(0x401162, hardware=True)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.regs.rip == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        self.assertEqual(bp4.hit_count, bp2.hit_count // 2 + 1)

        self.d.kill()

    def test_bps_running(self):
        d = self.d

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x40115B)
        bp3 = d.breakpoint(0x40116D)

        counter = 1

        d.cont()

        while True:
            if d.running:
                pass
            if d.regs.rip == bp1.address:
                self.assertFalse(d.running)
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.rip == bp2.address:
                self.assertFalse(d.running)
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.rip == bp3.address:
                self.assertFalse(d.running)
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.rsi == 45)
                self.assertTrue(d.regs.esi == 45)
                self.assertTrue(d.regs.si == 45)
                self.assertTrue(d.regs.sil == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        self.assertEqual(bp2.hit_count, 10)

        self.d.kill()

    def test_bp_backing_file(self):
        d = debugger("binaries/executable_section_test")

        d.run()

        bp1 = d.breakpoint(0x1266, file="binary")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps():
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.rip], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        bp1 = d.breakpoint(0x1266, file="executable_section_test")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps():
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.rip], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.run()

        bp1 = d.breakpoint(0x1266, file="hybrid")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps():
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0xD, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.rip], b"]")
            self.assertEqual(d.regs.rax, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        with self.assertRaises(ValueError):
            d.breakpoint(0x1266, file="absolute")

        d.kill()

    def test_bp_disable_on_creation(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.bp("random_function")
        bp2 = d.bp(0x40119c)
        bp1.disable()

        d.cont()

        assert not bp1.hit_on(d)
        assert bp2.hit_on(d)

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_2(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp = d.bp("random_function")

        bp.disable()

        d.cont()
        d.wait()

        # Validate we didn't segfault
        assert d.dead and d.exit_signal is None

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_hardware(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.bp("random_function", hardware=True)
        bp2 = d.bp(0x40119c)
        bp1.disable()

        d.cont()

        assert not bp1.hit_on(d)
        assert bp2.hit_on(d)

        d.kill()
        d.terminate()

    def test_bp_disable_on_creation_2_hardware(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp = d.bp("random_function", hardware=True)

        bp.disable()

        d.cont()
        d.wait()

        # Validate we didn't segfault
        assert d.dead and d.exit_signal is None

        d.kill()
        d.terminate()

if __name__ == "__main__":
    unittest.main()
