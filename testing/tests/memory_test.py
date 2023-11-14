#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

class MemoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.d = debugger("binaries/memory_test")

    def test_memory(self):
        global validated

        validated = False

        def bp_change_memory(d, _):
            address = d.rdi
            prev = bytes(range(256))

            self.assertTrue(d.memory[address:address + 256] == prev)

            d.memory[address + 128:] = b'abcd123456'

            prev = prev[:128] + b'abcd123456' + prev[138:]

            self.assertTrue(d.memory[address:address + 256] == prev)

        def bp_validate(d, _):
            global validated
            validated = True

        self.d.start()
        self.d.b("change_memory", bp_change_memory)
        self.d.b("validate_setter", bp_validate)
        self.d.cont()
        self.d.kill()
        self.assertTrue(validated)
