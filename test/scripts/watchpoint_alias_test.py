#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini, Gabriele Digregorio.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import unittest

from libdebug import debugger


class WatchpointAliasTest(unittest.TestCase):

    def test_watchpoint_alias(self):
        d = debugger("binaries/watchpoint_test", auto_interrupt_on_command=False)

        d.run()

        d.watchpoint("global_char", condition="rw", length=1)
        d.watchpoint("global_int", condition="w", length=4)
        d.watchpoint("global_long", condition="rw", length=8)

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
