#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import string
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        ADDRESS = 0x401209
    case "aarch64":
        ADDRESS = 0xa10
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")


class AntidebugEscapingTest(TestCase):
    def test_antidebug_escaping(self):
        d = debugger(RESOLVE_EXE("antidebug_brute_test"))

        # validate that without the handler the binary cannot be debugged
        r = d.run()
        d.cont()
        msg = r.recvline()
        self.assertEqual(msg, b"Debugger detected")
        d.kill()

        # validate that with the handler the binary can be debugged
        d = debugger(RESOLVE_EXE("antidebug_brute_test"), escape_antidebug=True)
        r = d.run()
        d.cont()
        msg = r.recvline()
        self.assertEqual(msg, b"Write up to 64 chars")
        d.interrupt()
        d.kill()

        # validate that the binary still works
        flag = ""
        counter = 1

        while not flag or flag != "BRUTE":
            for c in string.printable:
                r = d.run()
                bp = d.breakpoint(ADDRESS, hardware=True, file="binary")
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                while bp.address == d.instruction_pointer:
                    d.cont()

                if bp.hit_count > counter:
                    flag += c
                    counter = bp.hit_count
                    d.kill()
                    break

                message = r.recvline()

                d.kill()

                if message == b"Giusto!":
                    flag += c
                    break

        self.assertEqual(flag, "BRUTE")
        d.terminate()
