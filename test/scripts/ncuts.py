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
# ncuts - challenge from DEF CON CTF Quals 2023
# Thanks to the whole mhackeroni CTF team for the exploit
#
from libdebug import debugger



def get_passsphrase_from_class_1_binaries(previous_flag):
    global flag
    flag = b''

    def do_xor(d, b):
        global flag

        if b.hit_count <= 8:
            offset = ord('a') ^ d.rbp
            d.rbp = d.r13
            flag += (offset ^ d.r13).to_bytes(1, 'little')

    d = debugger('../CTF/1')
    r = d.start()
    
    d.b(0x7ef1, do_xor, hardware_assisted = True)
    d.cont()

    r.recvuntil(b'Passphrase:\n')
    r.send(previous_flag + b'a'*8)
    r.recvline()

    d.kill()

    assert flag == b'\x00\x006\x00\x00\x00(\x00'
    return flag



def get_passsphrase_from_class_2_binaries(previous_flag):
    global flag
    global bitmap 
    global lastpos

    bitmap = {}
    lastpos = 0
    flag = b''


    def get_value(d, b):
        global lastpos
        lastpos = d.rbp
        d.rbp = d.r13 + 1

    def assign(d, b):
        global bitmap 
        bitmap[d.r12 & 0xff] = lastpos & 0xff

    def get_flag(d, b):
        global flag
        
        d.rbp = d.r13 

        wanted = d.rbp
        needed = 0
        for i in range(8):
            if wanted & (2 ** i):
                needed |= bitmap[2 ** i]
        flag += chr(needed).encode('latin-1')


    d = debugger('../CTF/2')
    r = d.start()


    d.b(0xD8C1, get_value)
    d.b(0x1858, assign)
    d.b(0xDBA1, get_flag)

    d.cont()

    r.recvuntil(b'Passphrase:\n')
    r.send(previous_flag + b'a'*8)
    r.recvline()

    d.kill()

    assert flag == b'\x00\x00\x00\x01\x00\x00a\x00'



def get_passsphrase_from_class_3_binaries():
    global flag
    flag = b''

    def do_offset(d, b):
        global flag

        if b.hit_count <= 8:
            offset = ord('a') - d.rbp
            d.rbp = d.r13

            to_put = d.r13 + offset
            if to_put < 0:
                to_put += 256
            flag += chr(to_put).encode('latin-1')
            
    d = debugger('../CTF/0')
    r = d.start()

    r.send(b'a'*8)

    d.b(0x91A1, do_offset, hardware_assisted = True)
    d.cont()
    r.recvline()

    d.kill()
   
    assert flag == b'BM8\xd3\x02\x00\x00\x00'
    return flag


flag = get_passsphrase_from_class_3_binaries()
flag = get_passsphrase_from_class_1_binaries(flag)
get_passsphrase_from_class_2_binaries(flag)