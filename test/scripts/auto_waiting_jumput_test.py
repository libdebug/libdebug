#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


class AutoWaitingJumpoutTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
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
