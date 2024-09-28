#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import unittest

from libdebug import debugger


class BreakpointTest(unittest.TestCase):
    def setUp(self):
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
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x7fc, file="binary")
        bp3 = d.breakpoint(0x820, file="binary")

        counter = 1

        d.cont()

        while True:
            if d.regs.pc == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.pc == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        assert bp2.hit_count == 10

        d.kill()
        d.terminate()

    def test_bp_disable(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x7fc, file="binary")
        bp3 = d.breakpoint(0x820, file="binary")

        counter = 1

        d.cont()

        while True:
            if d.regs.pc == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.regs.pc == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        assert bp2.hit_count == 1

        d.kill()
        d.terminate()

    def test_bp_disable_hardware(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x7fc, file="binary", hardware=True)
        bp3 = d.breakpoint(0x820, file="binary")

        counter = 1

        d.cont()

        while True:
            if d.regs.pc == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                bp2.disable()
            elif d.regs.pc == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        assert bp2.hit_count == 1

        d.kill()
        d.terminate()

    def test_bp_disable_reenable(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x7fc, file="binary")
        bp4 = d.breakpoint(0x814, file="binary")
        bp3 = d.breakpoint(0x820, file="binary")

        counter = 1

        d.cont()

        while True:
            if d.regs.pc == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.regs.pc == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        assert bp3.hit_count == 1
        assert bp4.hit_count == (bp2.hit_count // 2 + 1)

        d.kill()
        d.terminate()

    def test_bp_disable_reenable_hardware(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function", hardware=True)
        bp2 = d.breakpoint(0x7fc, file="binary", hardware=True)
        bp4 = d.breakpoint(0x810, file="binary", hardware=True)
        bp3 = d.breakpoint(0x820, file="binary", hardware=True)

        counter = 1

        d.cont()

        for _ in range(20):
            if d.regs.pc == bp1.address:
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                if bp4.enabled:
                    bp4.disable()
                else:
                    bp4.enable()
                counter += 1
            elif d.regs.pc == bp3.address:
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break
            elif bp4.hit_on(d):
                pass

            d.cont()

        assert bp4.hit_count == (bp2.hit_count // 2 + 1)

        d.kill()
        d.terminate()

    def test_bps_running(self):
        d = debugger("binaries/breakpoint_test")

        d.run()

        bp1 = d.breakpoint("random_function")
        bp2 = d.breakpoint(0x7fc, file="binary")
        bp3 = d.breakpoint(0x820, file="binary")

        counter = 1

        d.cont()

        while True:
            if d.running:
                pass
            if d.regs.pc == bp1.address:
                self.assertFalse(d.running)
                self.assertTrue(bp1.hit_count == 1)
                self.assertTrue(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
            elif d.regs.pc == bp2.address:
                self.assertFalse(d.running)
                self.assertTrue(bp2.hit_count == counter)
                self.assertTrue(bp2.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp3.hit_on(d))
                counter += 1
            elif d.regs.pc == bp3.address:
                self.assertFalse(d.running)
                self.assertTrue(bp3.hit_count == 1)
                self.assertTrue(d.regs.w1 == 45)
                self.assertTrue(d.regs.x1 == 45)
                self.assertTrue(bp3.hit_on(d))
                self.assertFalse(bp1.hit_on(d))
                self.assertFalse(bp2.hit_on(d))
                break

            d.cont()

        assert bp2.hit_count == 10

        d.kill()
        d.terminate()

    def test_bp_backing_file(self):
        d = debugger("binaries/executable_section_test")

        d.run()

        bp1 = d.breakpoint(0x968, file="binary")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        bp1 = d.breakpoint(0x968, file="executable_section_test")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.run()

        bp1 = d.breakpoint(0x968, file="hybrid")

        d.cont()

        d.wait()

        if bp1.hit_on(d):
            for vmap in d.maps:
                if "x" in vmap.permissions and "anon" in vmap.backing_file:
                    section = vmap.backing_file
            bp2 = d.breakpoint(0x10, file=section)
            d.cont()

        d.wait()

        if bp2.hit_on(d):
            self.assertEqual(d.memory[d.regs.pc, 4], bytes.fromhex("ff430091"))
            self.assertEqual(d.regs.w0, 9)

        d.kill()

        self.assertEqual(bp1.hit_count, 1)
        self.assertEqual(bp2.hit_count, 1)

        d.run()

        with self.assertRaises(ValueError):
            d.breakpoint(0x968, file="absolute")

        d.kill()
        d.terminate()
