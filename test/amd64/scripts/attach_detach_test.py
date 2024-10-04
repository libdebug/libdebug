#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import logging
import unittest

import subprocess
from pwn import process
from libdebug import debugger

logging.getLogger("pwnlib").setLevel(logging.ERROR)


class AttachDetachTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_attach(self):
        r = process("binaries/attach_test")

        d = debugger()
        d.attach(r.pid)
        bp = d.breakpoint("printName", hardware=True)
        d.cont()

        r.recvuntil(b"name:")
        r.sendline(b"Io_no")

        self.assertTrue(d.regs.rip == bp.address)

        d.cont()

        d.kill()
        
    def test_attach_multithread(self):
        r = subprocess.Popen(["binaries/multithread_input"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Synchronize with the process to be sure that all threads have been created
        while b"All threads have been created." not in r.stdout.readline():
            pass
        
        d = debugger()
        d.attach(r.pid)
        
        # Breakpoint at the end of the thread function
        bp = d.breakpoint(0x128a, hardware=True, callback=lambda _, __: _, file="binary")
        
        self.assertEqual(len(d.threads), 6)
        
        d.cont()
        
        for _ in range(5):
            r.stdin.write(b"1\n")
            r.stdin.flush()

        d.detach()
        r.kill()
        
        self.assertEqual(bp.hit_count, 5)

    def test_attach_and_detach_1(self):
        r = process("binaries/attach_test")

        d = debugger()

        # Attach to the process
        d.attach(r.pid)
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        r.kill()

    def test_attach_and_detach_2(self):
        d = debugger("binaries/attach_test")

        # Run the process
        r = d.run()
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        d.kill()

    def test_attach_and_detach_3(self):
        d = debugger("binaries/attach_test")

        r = d.run()

        # We must ensure that any breakpoint is unset before detaching
        d.breakpoint(0x125E)
        d.breakpoint(0x1261, hardware=True)

        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        d.kill()

    def test_attach_and_detach_4(self):
        r = process("binaries/attach_test")

        d = debugger()
        d.attach(r.pid)
        d.detach()
        d.kill()

        # Validate that, after detaching and killing, the process is effectively terminated
        self.assertRaises(EOFError, r.sendline, b"provola")


if __name__ == "__main__":
    unittest.main()
