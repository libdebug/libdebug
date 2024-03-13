#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini.
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
import unittest

from libdebug import debugger


class CallbackTest(unittest.TestCase):
    def setUp(self):
        self.exceptions = []

    def test_callback_simple(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/basic_test")

        d.run()

        def callback(thread, bp):
            global hit

            try:
                self.assertEqual(bp.hit_count, 1)
                self.assertTrue(bp.hit_on(thread))
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("register_test", callback=callback)

        d.cont()

        d.wait()

        d.kill()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_simple_hardware(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/basic_test")

        d.run()

        def callback(thread, bp):
            global hit

            try:
                self.assertEqual(bp.hit_count, 1)
                self.assertTrue(bp.hit_on(thread))
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("register_test", callback=callback, hardware=True)

        d.cont()

        d.wait()

        d.kill()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_memory(self):
        self.exceptions.clear()

        global hit
        hit = False

        d = debugger("binaries/memory_test")

        d.run()

        def callback(thread, bp):
            global hit

            prev = bytes(range(256))
            try:
                self.assertEqual(bp.address, thread.rip)
                self.assertEqual(bp.hit_count, 1)
                self.assertEqual(thread.memory[thread.rdi, 256], prev)

                thread.memory[thread.rdi + 128 :] = b"abcd123456"
                prev = prev[:128] + b"abcd123456" + prev[138:]

                self.assertEqual(thread.memory[thread.rdi, 256], prev)
            except Exception as e:
                self.exceptions.append(e)

            hit = True

        d.breakpoint("change_memory", callback=callback)

        d.cont()

        d.wait()

        d.kill()

        self.assertTrue(hit)

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_bruteforce(self):
        global flag
        global counter
        global new_counter

        flag = ""
        counter = 1
        new_counter = 0

        def brute_force(d, b):
            global new_counter
            try:
                new_counter = b.hit_count
            except Exception as e:
                self.exceptions.append(e)

        d = debugger("binaries/brute_test")
        while True:
            end = False
            for c in string.printable:
                r = d.run()

                d.breakpoint(0x1222, callback=brute_force, hardware=True)
                d.cont()

                r.sendlineafter(b"chars\n", (flag + c).encode())

                d.wait()

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

        self.assertEqual(flag, "BRUTINOBRUTONE")

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_jumpout(self):
        global flag
        global first
        global second

        flag = ""
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
                third = int.from_bytes(d.memory[address : address + 1], "little")
                flag += chr((first ^ second ^ third ^ (b.hit_count - 1)))
            except Exception as e:
                self.exceptions.append(e)

        d = debugger("CTF/jumpout")
        r = d.run()

        d.breakpoint(0x140B, callback=second, hardware=True)
        d.breakpoint(0x157C, callback=third, hardware=True)
        d.cont()

        r.sendline(b"A" * 0x1D)
        r.recvuntil(b"Wrong...")

        d.wait()

        d.kill()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

        if self.exceptions:
            raise self.exceptions[0]

    def test_callback_intermixing(self):
        global secval

        flag = ""
        first = 0x55

        d = debugger("CTF/jumpout")
        r = d.run()

        def second(d, b):
            global secval
            try:
                secval = d.r9
            except Exception as e:
                self.exceptions.append(e)

        d.breakpoint(0x140B, callback=second, hardware=True)
        bp = d.breakpoint(0x157C, hardware=True)

        d.cont()

        r.sendline(b"A" * 0x1D)

        while True:
            d.wait()

            if d.rip == bp.address:
                address = d.r13 + d.rbx
                third = int.from_bytes(d.memory[address : address + 1], "little")
                flag += chr((first ^ secval ^ third ^ (bp.hit_count - 1)))

            d.cont()

            if flag.endswith("}"):
                break

        r.recvuntil(b"Wrong...")

        d.kill()

        self.assertEqual(flag, "SECCON{jump_table_everywhere}")

        if self.exceptions:
            raise self.exceptions[0]
