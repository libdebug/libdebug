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
# vmwhere1 - challenge from UIUCTF 2023
#

from libdebug import debugger
import string
import unittest


class Vmwhere1(unittest.TestCase):
    def setUp(self):
        self.exceptions = []

    def test_vmwhere1(self):
        global flag
        global current_counter
        global added

        flag = b''
        current_counter = 3

        def brute_force(d,b):
            global current_counter
            global added
            global flag
            try:
                if b.hit_count > current_counter:
                    current_counter = b.hit_count
                    if not added:
                        flag += el.encode()
                    added = True
            except Exception as e:
                self.exceptions.append(e)

        d = debugger(['CTF/vmwhere1', 'CTF/vmwhere1_program'])
        while True:
            added = False
            stop = False
            for el in string.printable:
                r = d.start()
                d.b(0x1587, brute_force, hardware_assisted=True)
                d.cont()

                r.recvline()
                r.recvuntil(b'the password:\n')

                r.sendline(flag + el.encode())

                message = r.recvline()
                if b'Incorrect' not in message:
                    stop = True
                    added = True
                    flag += el.encode()

                d.kill()

                if added:
                    break
            
            if stop:
                break

        assert flag == b'uiuctf{ar3_y0u_4_r3al_vm_wh3r3_(gpt_g3n3r4t3d_th1s_f14g)}'

        if self.exceptions:
            raise self.exceptions[0]

if __name__ == '__main__':
    unittest.main()