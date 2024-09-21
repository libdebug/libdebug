#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Francesco Panebianco, Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class WatchpointTest(unittest.TestCase):
    def test_watchpoint(self):
        d = debugger("binaries/watchpoint_test", auto_interrupt_on_command=False)

        d.run()

        d.breakpoint("global_char", hardware=True, condition="rw", length=1)
        d.breakpoint("global_int", hardware=True, condition="w", length=4)
        d.breakpoint("global_short", hardware=True, condition="r", length=2)
        d.breakpoint("global_long", hardware=True, condition="rw", length=8)

        d.cont()

        base = d.regs.pc & ~0xfff

        # strb w1, [x0] => global_char
        self.assertEqual(d.regs.pc, base + 0x724)

        d.cont()

        # str w1, [x0] => global_int
        self.assertEqual(d.regs.pc, base + 0x748)

        d.cont()

        # str x1, [x0] => global_long
        self.assertEqual(d.regs.pc, base + 0x764)

        d.cont()

        # ldrb w0, [x0] => global_char
        self.assertEqual(d.regs.pc, base + 0x780)

        d.cont()

        # ldr w0, [x0] => global_short
        self.assertEqual(d.regs.pc, base + 0x790)

        d.cont()

        # ldr x0, [x0] => global_long
        self.assertEqual(d.regs.pc, base + 0x7b0)

        d.cont()

        d.kill()

    def test_watchpoint_callback(self):
        global_char_ip = []
        global_int_ip = []
        global_short_ip = []
        global_long_ip = []

        def watchpoint_global_char(t, b):
            nonlocal global_char_ip

            global_char_ip.append(t.regs.pc)

        def watchpoint_global_int(t, b):
            nonlocal global_int_ip

            global_int_ip.append(t.regs.pc)

        def watchpoint_global_short(t, b):
            nonlocal global_short_ip

            global_short_ip.append(t.regs.pc)

        def watchpoint_global_long(t, b):
            nonlocal global_long_ip

            global_long_ip.append(t.regs.pc)

        d = debugger("binaries/watchpoint_test", auto_interrupt_on_command=False)

        d.run()

        base = d.regs.pc & ~0xfff

        wp1 = d.breakpoint(
            "global_char",
            hardware=True,
            condition="rw",
            length=1,
            callback=watchpoint_global_char,
        )
        wp2 = d.breakpoint(
            "global_int",
            hardware=True,
            condition="w",
            length=4,
            callback=watchpoint_global_int,
        )
        wp3 = d.breakpoint(
            "global_long",
            hardware=True,
            condition="rw",
            length=8,
            callback=watchpoint_global_long,
        )
        wp4 = d.breakpoint(
            "global_short",
            hardware=True,
            condition="r",
            length=2,
            callback=watchpoint_global_short,
        )

        d.cont()

        d.kill()

        # strb w1, [x0] => global_char
        self.assertEqual(global_char_ip[0], base + 0x724)

        # str w1, [x0] => global_int
        self.assertEqual(global_int_ip[0], base + 0x748)

        # str x1, [x0] => global_long
        self.assertEqual(global_long_ip[0], base + 0x764)

        # ldrb w0, [x0] => global_char
        self.assertEqual(global_char_ip[1], base + 0x780)

        # ldr w0, [x0] => global_short
        self.assertEqual(global_short_ip[0], base + 0x790)

        # ldr x0, [x0] => global_long
        self.assertEqual(global_long_ip[1], base + 0x7b0)

        self.assertEqual(len(global_char_ip), 2)
        self.assertEqual(len(global_int_ip), 1)
        self.assertEqual(len(global_short_ip), 1)
        self.assertEqual(len(global_long_ip), 2)
        self.assertEqual(wp1.hit_count, 2)
        self.assertEqual(wp2.hit_count, 1)
        self.assertEqual(wp3.hit_count, 2)
        self.assertEqual(wp4.hit_count, 1)

