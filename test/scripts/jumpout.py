#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Gabriele Digregorio.
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
        
#
# jumpout - challenge from SECCON CTF 2023
#

from pwn import *
from libdebug import debugger
import unittest


class Jumpout(unittest.TestCase):
    def setUp(self):
        self.exceptions = []

    def test_jumpout(self):
        global flag
        global first
        global second

        flag = ''
        first = 0x55

        def second(d, b):
            global second
            try:
                second = d.r9
            except Exception as e:
                self.exceptions.append(e)      
        
        def third(d, b):
            global flag
            try:
                address = d.r13 + d.rbx    
                third = int.from_bytes(d.memory[address:address+1], 'little')
                flag += chr((first ^ second ^ third ^ (b.hit_count - 1)))
            except Exception as e:
                self.exceptions.append(e)

        d = debugger('CTF/jumpout')
        r = d.start()

        d.b(0x140b, second, hardware_assisted=True)
        d.b(0x157c, third, hardware_assisted=True)
        d.cont()

        r.sendline(b"A"*0x1d)
        r.recvuntil(b'Wrong...')

        d.kill()
        assert flag == 'SECCON{jump_table_everywhere}'

        if self.exceptions:
            raise self.exceptions[0]

if __name__ == '__main__':
    unittest.main() 