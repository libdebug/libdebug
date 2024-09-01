#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import string
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        ADDRESS = 0x1222
    case "aarch64":
        ADDRESS = 0x974
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")

class BruteTest(TestCase):
    def setUp(self):
        self.exceptions = []

    def test_bruteforce(self):
        flag = ""
        counter = 1

        d = debugger(RESOLVE_EXE("brute_test"))

        while not flag or flag != "BRUTINOBRUTONE":
            for c in string.printable:
                r = d.run()
                bp = d.breakpoint(ADDRESS, hardware=True)
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

        self.assertEqual(flag, "BRUTINOBRUTONE")
        d.terminate()

    def test_callback_bruteforce(self):
        global flag
        global counter
        global new_counter

        flag = ""
        counter = 1
        new_counter = 0

        def brute_force(d, b):
            global new_counter
            try:
                new_counter = b.hit_count
            except Exception as e:
                self.exceptions.append(e)

        d = debugger(RESOLVE_EXE("brute_test"))
        while True:
            end = False
            for c in string.printable:
                r = d.run()

                d.breakpoint(ADDRESS, callback=brute_force, hardware=True)
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                message = r.recvline()

                if new_counter > counter:
                    flag += c
                    counter = new_counter
                    d.kill()
                    break
                d.kill()
                if message == b"Giusto!":
                    flag += c
                    end = True
                    break
            if end:
                break

        self.assertEqual(flag, "BRUTINOBRUTONE")
        d.terminate()

        if self.exceptions:
            raise self.exceptions[0]
