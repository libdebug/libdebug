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

from libdebug import debugger
from pwn import *
import unittest
import logging

logging.getLogger('pwnlib').setLevel(logging.ERROR)

class AttachTest(unittest.TestCase):
    def setUp(self):
        self.exceptions = []
        
    def test_attach(self):
        global is_hit

        def hook(d,b):
            global is_hit
            try:
                is_hit = True
            except Exception as e:
                self.exceptions.append(e)
        
        r = process('binaries/attach_test')

        d = debugger()
        d.attach(r.pid)
        d.b('printName', hook, hardware_assisted=True)
        d.cont()

        r.recvuntil(b'name:')
        r.sendline(b'Io_no')

        d.kill()
        
        self.assertTrue(is_hit)
        if self.exceptions:
            raise self.exceptions[0]