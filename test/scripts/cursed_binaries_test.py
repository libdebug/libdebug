#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class CursedBinariesTest(TestCase):
    def test_cursed_ldpreload(self):
        d = debugger(RESOLVE_EXE("jumpstart_test"), env={"LD_PRELOAD": RESOLVE_EXE("jumpstart_test_preload.so")})

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Preload library loaded")
        self.assertEqual(r.recvline(), b"Jumpstart test")
        self.assertEqual(r.recvline(), b"execve(/bin/ls, (nil), (nil))")

        d.kill()
        d.terminate()

    def test_argv0_different_from_pathname(self):
        d = debugger(["abcd", "provola", "test"], path=RESOLVE_EXE("pathname_argv_test"))

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"argc: 3")
        self.assertEqual(r.recvline(), b"argv[0]: abcd")
        self.assertEqual(r.recvline(), b"argv[1]: provola")
        self.assertEqual(r.recvline(), b"argv[2]: test")

        d.kill()
        d.terminate()
