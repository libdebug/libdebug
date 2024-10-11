#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

#
# deep-dive-division - challenge from KalmarCTF 2024
#

import string
from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger


class DeepDiveDivisionTest(TestCase):
    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_deep_dive_division_recvline(self):
        def brutone(flag, current):
            def checkino(d, b):
                nonlocal counter
                if int.from_bytes(d.memory[d.regs.rax + d.regs.r9, 1, "absolute"], "little") == 0:
                    counter += 1

            candidate = []
            for c in string.printable:
                counter = 0
                r = d.run()
                d.breakpoint(0x4012F2, hardware=True, callback=checkino)
                d.cont()
                r.sendlineafter(b"flag?", flag + c.encode())
                r.recvline(2)

                d.kill()
                if counter > current:
                    candidate.append(c)
            return candidate

        d = debugger(RESOLVE_EXE("CTF/deep-dive-division"))
        candidate = {}

        flag = b""
        current = 6

        candidate = brutone(flag, current)
        while True:
            if len(candidate) == 0:
                break
            elif len(candidate) == 1:
                current += 1
                flag += candidate[0].encode()
                candidate = brutone(flag, current)
            else:
                current += 1

                for c in candidate:
                    flag_ = flag + c.encode()
                    candidate = brutone(flag_, current)
                    if candidate != []:
                        flag = flag_
                        break

        self.assertEqual(flag, b"kalmar{vm_in_3d_space!_cb3992b605aafe137}\n")
        
    def test_deep_dive_division_recv(self):
        def brutone(flag, current):
            def checkino(d, b):
                nonlocal counter
                if int.from_bytes(d.memory[d.regs.rax + d.regs.r9, 1, "absolute"], "little") == 0:
                    counter += 1

            candidate = []
            for c in string.printable:
                counter = 0
                r = d.run()
                d.breakpoint(0x4012F2, hardware=True, callback=checkino)
                d.cont()
                r.sendlineafter(b"flag?", flag + c.encode())
                r.recv(11)

                d.kill()
                if counter > current:
                    candidate.append(c)
            return candidate

        d = debugger(RESOLVE_EXE("CTF/deep-dive-division"))
        candidate = {}

        flag = b""
        current = 6

        candidate = brutone(flag, current)
        while True:
            if len(candidate) == 0:
                break
            elif len(candidate) == 1:
                current += 1
                flag += candidate[0].encode()
                candidate = brutone(flag, current)
            else:
                current += 1

                for c in candidate:
                    flag_ = flag + c.encode()
                    candidate = brutone(flag_, current)
                    if candidate != []:
                        flag = flag_
                        break

        self.assertEqual(flag, b"kalmar{vm_in_3d_space!_cb3992b605aafe137}\n")
