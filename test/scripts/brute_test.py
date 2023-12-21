#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Gabriele Digregorio, Francesco Panebianco.
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

import string
from libdebug import debugger
import unittest


class BruteTest(unittest.TestCase):
    def setUp(self):
        self.exceptions = []

    def test_bruteforce(self):
        global flag
        global counter
        global new_counter

        flag = ''
        counter = 1
        new_counter = 0

        def brute_force(d,b):
            global new_counter 
            try:
                new_counter = b.hit_count
            except Exception as e:
                self.exceptions.append(e)

        d = debugger('binaries/brute_test')
        while True:
            end = False
            for c in string.printable:

                r = d.start()

                d.b(0x1222, brute_force, hardware_assisted=True)
                d.cont()
                
                r.sendlineafter(b'chars\n', (flag+c).encode())
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
        
        assert flag == 'BRUTINOBRUTONE'

        if self.exceptions:
            raise self.exceptions[0]


if __name__ == '__main__':
    unittest.main()