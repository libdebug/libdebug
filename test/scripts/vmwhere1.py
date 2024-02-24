#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Roberto Alessandro Bertolini.
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

import string
import unittest

from libdebug import debugger


class Vmwhere1(unittest.TestCase):
    def setUp(self):
        pass

    def test_vmwhere1(self):
        flag = b""
        counter = 3
        stop = False

        d = debugger(["CTF/vmwhere1", "CTF/vmwhere1_program"])

        while not stop:
            for el in string.printable:
                r = d.run()
                bp = d.breakpoint(0x1587, hardware=True)
                d.cont()

                r.recvline()
                r.recvuntil(b"the password:\n")

                r.sendline(flag + el.encode())

                d.wait()

                while d.rip == bp.address:
                    d.cont()
                    d.wait()

                message = r.recvline()

                if b"Incorrect" not in message:
                    flag += el.encode()
                    stop = True
                    d.kill()
                    break
                else:
                    if bp.hit_count > counter:
                        counter = bp.hit_count
                        flag += el.encode()
                        d.kill()
                        break

                d.kill()

        self.assertEqual(
            flag, b"uiuctf{ar3_y0u_4_r3al_vm_wh3r3_(gpt_g3n3r4t3d_th1s_f14g)}"
        )


if __name__ == "__main__":
    unittest.main()
