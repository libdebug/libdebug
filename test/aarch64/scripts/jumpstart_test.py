#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger

class JumpstartTest(unittest.TestCase):

    def test_cursed_ldpreload(self):
        d = debugger("binaries/jumpstart_test", env={"LD_PRELOAD": "binaries/jumpstart_test_preload.so"})

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Preload library loaded")
        self.assertEqual(r.recvline(), b"Jumpstart test")
        self.assertEqual(r.recvline(), b"execve(/bin/ls, (nil), (nil))")

        d.kill()
