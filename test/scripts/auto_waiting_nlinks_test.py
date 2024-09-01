#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


class AutoWaitingNlinksTest(TestCase):
    def get_passsphrase_from_class_1_binaries(self, previous_flag):
        flag = b""

        d = debugger(RESOLVE_EXE("CTF/1"), auto_interrupt_on_command=False)
        r = d.run()

        d.breakpoint(0x7EF1, hardware=True, file="binary")

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        for _ in range(8):
            offset = ord("a") ^ d.regs.rbp
            d.regs.rbp = d.regs.r13
            flag += (offset ^ d.regs.r13).to_bytes(1, "little")

            d.cont()

        r.recvline()

        d.kill()
        d.terminate()

        self.assertEqual(flag, b"\x00\x006\x00\x00\x00(\x00")
        return flag

    def get_passsphrase_from_class_2_binaries(self, previous_flag):
        bitmap = {}
        lastpos = 0
        flag = b""

        d = debugger(RESOLVE_EXE("CTF/2"), auto_interrupt_on_command=False)
        r = d.run()

        bp1 = d.breakpoint(0xD8C1, hardware=True, file="binary")
        bp2 = d.breakpoint(0x1858, hardware=True, file="binary")
        bp3 = d.breakpoint(0xDBA1, hardware=True, file="binary")

        d.cont()

        r.recvuntil(b"Passphrase:\n")
        r.send(previous_flag + b"a" * 8)

        while True:
            if d.regs.rip == bp1.address:
                lastpos = d.regs.rbp
                d.regs.rbp = d.regs.r13 + 1
            elif d.regs.rip == bp2.address:
                bitmap[d.regs.r12 & 0xFF] = lastpos & 0xFF
            elif d.regs.rip == bp3.address:
                d.regs.rbp = d.regs.r13
                wanted = d.regs.rbp
                needed = 0
                for i in range(8):
                    if wanted & (2**i):
                        needed |= bitmap[2**i]
                flag += chr(needed).encode()

                if bp3.hit_count == 8:
                    d.cont()
                    break

            d.cont()

        d.kill()
        d.terminate()

        self.assertEqual(flag, b"\x00\x00\x00\x01\x00\x00a\x00")

    def get_passsphrase_from_class_3_binaries(self):
        flag = b""

        d = debugger(RESOLVE_EXE("CTF/0"), auto_interrupt_on_command=False)
        r = d.run()

        d.breakpoint(0x91A1, hardware=True, file="binary")

        d.cont()

        r.send(b"a" * 8)

        for _ in range(8):
            offset = ord("a") - d.regs.rbp
            d.regs.rbp = d.regs.r13

            flag += chr((d.regs.r13 + offset) % 256).encode("latin-1")

            d.cont()

        r.recvline()

        d.kill()
        d.terminate()

        self.assertEqual(flag, b"BM8\xd3\x02\x00\x00\x00")
        return flag

    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_nlinks(self):
        flag = self.get_passsphrase_from_class_3_binaries()
        flag = self.get_passsphrase_from_class_1_binaries(flag)
        self.get_passsphrase_from_class_2_binaries(flag)
