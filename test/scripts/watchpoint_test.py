#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Francesco Panebianco, Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


class WatchpointTest(TestCase):
    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_amd64(self):
        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

        wp_char = d.breakpoint("global_char", hardware=True, condition="rw", length=1)
        wp_int = d.breakpoint("global_int", hardware=True, condition="w", length=4)
        wp_long = d.breakpoint("global_long", hardware=True, condition="rw", length=8)

        d.cont()
 
        self.assertEqual(d.regs.rip, 0x401111)  # mov byte ptr [global_char], 0x1
        self.assertTrue(wp_char.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 0)
        self.assertEqual(wp_long.hit_count, 0)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401124)  # mov dword ptr [global_int], 0x4050607
        self.assertTrue(wp_int.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 0)

        d.cont()

        self.assertEqual(
            d.regs.rip, 0x401135
        )  # mov qword ptr [global_long], 0x8090a0b0c0d0e0f
        self.assertTrue(wp_long.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 1)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401155)  # movzx eax, byte ptr [global_char]
        self.assertTrue(wp_char.hit_on(d))
        self.assertEqual(wp_char.hit_count, 2)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 1)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401173)  # mov rax, qword ptr [global_long]
        self.assertTrue(wp_long.hit_on(d))
        self.assertEqual(wp_char.hit_count, 2)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 2)

        d.cont()

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_callback_amd64(self):
        global_char_ip = []
        global_int_ip = []
        global_long_ip = []

        def watchpoint_global_char(t, b):
            nonlocal global_char_ip

            global_char_ip.append(t.instruction_pointer)

        def watchpoint_global_int(t, b):
            nonlocal global_int_ip

            global_int_ip.append(t.instruction_pointer)

        def watchpoint_global_long(t, b):
            nonlocal global_long_ip

            global_long_ip.append(t.instruction_pointer)

        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

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

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(global_char_ip[0], 0x401111)  # mov byte ptr [global_char], 0x1
        self.assertEqual(
            global_int_ip[0], 0x401124
        )  # mov dword ptr [global_int], 0x4050607
        self.assertEqual(
            global_long_ip[0], 0x401135
        )  # mov qword ptr [global_long], 0x8090a0b0c0d0e0f
        self.assertEqual(
            global_char_ip[1], 0x401155
        )  # movzx eax, byte ptr [global_char]
        self.assertEqual(
            global_long_ip[1], 0x401173
        )  # mov rax, qword ptr [global_long]

        self.assertEqual(len(global_char_ip), 2)
        self.assertEqual(len(global_int_ip), 1)

        # There is one extra hit performed by the exit routine of libc
        self.assertEqual(len(global_long_ip), 3)

        self.assertEqual(wp1.hit_count, 2)
        self.assertEqual(wp2.hit_count, 1)

        # There is one extra hit performed by the exit routine of libc
        self.assertEqual(wp3.hit_count, 3)

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_disable_amd64(self):
        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

        wp_char = d.breakpoint("global_char", hardware=True, condition="rw", length=1)
        wp_int = d.breakpoint("global_int", hardware=True, condition="w", length=4)
        wp_long = d.breakpoint("global_long", hardware=True, condition="rw", length=8)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401111)  # mov byte ptr [global_char], 0x1
        self.assertTrue(wp_char.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 0)
        self.assertEqual(wp_long.hit_count, 0)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401124)  # mov dword ptr [global_int], 0x4050607
        self.assertTrue(wp_int.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 0)

        d.cont()

        self.assertEqual(
            d.regs.rip, 0x401135
        )  # mov qword ptr [global_long], 0x8090a0b0c0d0e0f
        self.assertTrue(wp_long.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 1)

        # disable watchpoint
        wp_char.disable()

        d.cont()

        self.assertEqual(d.regs.rip, 0x401173)  # mov rax, qword ptr [global_long]
        self.assertTrue(wp_long.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 2)

        d.cont()

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_disable_reenable_amd64(self):
        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

        wp_char = d.breakpoint("global_char", hardware=True, condition="rw", length=1)
        wp_int = d.breakpoint("global_int", hardware=True, condition="w", length=4)
        wp_long = d.breakpoint("global_long", hardware=True, condition="rw", length=8)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401111)  # mov byte ptr [global_char], 0x1
        self.assertTrue(wp_char.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 0)
        self.assertEqual(wp_long.hit_count, 0)

        d.cont()

        self.assertEqual(d.regs.rip, 0x401124)  # mov dword ptr [global_int], 0x4050607
        self.assertTrue(wp_int.hit_on(d))
        self.assertEqual(wp_char.hit_count, 1)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 0)

        # disable watchpoint
        wp_long.disable()

        d.cont()


        self.assertEqual(d.regs.rip, 0x401155)  # movzx eax, byte ptr [global_char]
        self.assertTrue(wp_char.hit_on(d))
        self.assertEqual(wp_char.hit_count, 2)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 0)

        # re-enable watchpoint
        wp_long.enable()

        d.cont()

        self.assertEqual(d.regs.rip, 0x401173)  # mov rax, qword ptr [global_long]
        self.assertTrue(wp_long.hit_on(d))
        self.assertEqual(wp_char.hit_count, 2)
        self.assertEqual(wp_int.hit_count, 1)
        self.assertEqual(wp_long.hit_count, 1)

        d.cont()

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_alias_amd64(self):
        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

        d.wp("global_char", condition="rw", length=1)
        d.watchpoint("global_int", condition="w", length=4)
        d.watchpoint("global_long", condition="rw", length=8)

        d.cont()

        self.assertEqual(d.instruction_pointer, 0x401111)  # mov byte ptr [global_char], 0x1

        d.cont()

        self.assertEqual(d.instruction_pointer, 0x401124)  # mov dword ptr [global_int], 0x4050607

        d.cont()

        self.assertEqual(d.instruction_pointer, 0x401135)  # mov qword ptr [global_long], 0x8090a0b0c0d0e0f

        d.cont()

        self.assertEqual(d.instruction_pointer, 0x401155)  # movzx eax, byte ptr [global_char]

        d.cont()

        self.assertEqual(d.instruction_pointer, 0x401173)  # mov rax, qword ptr [global_long]

        d.cont()

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_watchpoint_callback_amd64(self):
        global_char_ip = []
        global_int_ip = []
        global_long_ip = []

        def watchpoint_global_char(t, b):
            nonlocal global_char_ip

            global_char_ip.append(t.instruction_pointer)

        def watchpoint_global_int(t, b):
            nonlocal global_int_ip

            global_int_ip.append(t.instruction_pointer)

        def watchpoint_global_long(t, b):
            nonlocal global_long_ip

            global_long_ip.append(t.instruction_pointer)

        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

        d.run()

        wp1 = d.watchpoint("global_char", condition="rw", length=1, callback=watchpoint_global_char)
        wp2 = d.wp("global_int", condition="w", length=4, callback=watchpoint_global_int)
        wp3 = d.watchpoint("global_long", condition="rw", length=8, callback=watchpoint_global_long)

        d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(global_char_ip[0], 0x401111)  # mov byte ptr [global_char], 0x1
        self.assertEqual(global_int_ip[0], 0x401124)  # mov dword ptr [global_int], 0x4050607
        self.assertEqual(global_long_ip[0], 0x401135)  # mov qword ptr [global_long], 0x8090a0b0c0d0e0f
        self.assertEqual(global_char_ip[1], 0x401155)  # movzx eax, byte ptr [global_char]
        self.assertEqual(global_long_ip[1], 0x401173)  # mov rax, qword ptr [global_long]

        self.assertEqual(len(global_char_ip), 2)
        self.assertEqual(len(global_int_ip), 1)

        # There is one extra hit performed by the exit routine of libc
        self.assertEqual(len(global_long_ip), 3)

        self.assertEqual(wp1.hit_count, 2)
        self.assertEqual(wp2.hit_count, 1)

        # There is one extra hit performed by the exit routine of libc
        self.assertEqual(wp3.hit_count, 3)

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_watchpoint_aarch64(self):
        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

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

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_watchpoint_callback_aarch64(self):
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

        d = debugger(RESOLVE_EXE("watchpoint_test"), auto_interrupt_on_command=False)

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
        d.terminate()

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
