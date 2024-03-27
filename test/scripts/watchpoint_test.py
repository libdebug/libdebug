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
        d.breakpoint("global_long", hardware=True, condition="rw", length=8)

        d.cont()

        self.assertEqual(d.rip, 0x401111) # mov byte ptr [global_char], 0x1

        d.cont()

        self.assertEqual(d.rip, 0x401124) # mov dword ptr [global_int], 0x4050607

        d.cont()

        self.assertEqual(d.rip, 0x401135) # mov qword ptr [global_long], 0x8090a0b0c0d0e0f

        d.cont()

        self.assertEqual(d.rip, 0x401155) # movzx eax, byte ptr [global_char]

        d.cont()

        self.assertEqual(d.rip, 0x401173) # mov rax, qword ptr [global_long]

        d.cont()

        d.kill()
