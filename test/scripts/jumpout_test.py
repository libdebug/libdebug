#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

#
# jumpout - challenge from SECCON CTF 2023
#

from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


class JumpoutTest(TestCase):
    def setUp(self):
        self.exceptions = []

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_jumpout(self):
        flag = ""
        first = 0x55
        second = 0

        d = debugger(RESOLVE_EXE("CTF/jumpout"))

        r = d.run()

        bp1 = d.breakpoint(0x140B, hardware=True, file="binary")
        bp2 = d.breakpoint(0x157C, hardware=True, file="binary")

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            if d.regs.rip == bp1.address:
                second = d.regs.r9
            elif d.regs.rip == bp2.address:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address, 1], "little")
                flag += chr((first ^ second ^ third ^ (bp2.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()
        d.terminate()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_callback_jumpout(self):
        global flag
        global first
        global second

        flag = ""
        first = 0x55

        def second(d, b):
            global second
            try:
                second = d.regs.r9
            except Exception as e:
                self.exceptions.append(e)

        def third(d, b):
            global flag
            try:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address : address + 1], "little")
                flag += chr((first ^ second ^ third ^ (b.hit_count - 1)))
            except Exception as e:
                self.exceptions.append(e)

        d = debugger(RESOLVE_EXE("CTF/jumpout"))
        r = d.run()

        d.breakpoint(0x140B, callback=second, hardware=True)
        d.breakpoint(0x157C, callback=third, hardware=True)
        d.cont()

        r.sendline(b"A" * 0x1D)
        r.recvuntil(b"Wrong...")

        d.kill()
        d.terminate()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

        if self.exceptions:
            raise self.exceptions[0]

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_callback_intermixing(self):
        global secval

        flag = ""
        first = 0x55

        d = debugger(RESOLVE_EXE("CTF/jumpout"))
        r = d.run()

        def second(d, b):
            global secval
            try:
                secval = d.regs.r9
            except Exception as e:
                self.exceptions.append(e)

        d.breakpoint(0x140B, callback=second, hardware=True)
        bp = d.breakpoint(0x157C, hardware=True)

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            if d.instruction_pointer == bp.address:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address : address + 1], "little")
                flag += chr((first ^ secval ^ third ^ (bp.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()
        d.terminate()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

        if self.exceptions:
            raise self.exceptions[0]

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_jumpout_auto_waiting(self):
        flag = ""
        first = 0x55
        second = 0

        d = debugger(RESOLVE_EXE("CTF/jumpout"), auto_interrupt_on_command=False)

        r = d.run()

        bp1 = d.breakpoint(0x140B, hardware=True, file="binary")
        bp2 = d.breakpoint(0x157C, hardware=True, file="binary")

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            if d.regs.rip == bp1.address:
                second = d.regs.r9
            elif d.regs.rip == bp2.address:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address, 1], "little")
                flag += chr((first ^ second ^ third ^ (bp2.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()
        d.terminate()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_jumpout_waiting(self):
        flag = ""
        first = 0x55
        second = 0

        d = debugger(RESOLVE_EXE("CTF/jumpout"), auto_interrupt_on_command=True)

        r = d.run()

        bp1 = d.breakpoint(0x140B, hardware=True, file="binary")
        bp2 = d.breakpoint(0x157C, hardware=True, file="binary")

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            d.wait()
            if d.instruction_pointer == bp1.address:
                second = d.regs.r9
            elif d.instruction_pointer == bp2.address:
                address = d.regs.r13 + d.regs.rbx
                third = int.from_bytes(d.memory[address, 1], "little")
                flag += chr((first ^ second ^ third ^ (bp2.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()
        d.terminate()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")
