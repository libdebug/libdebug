#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import logging
import unittest

import subprocess
from pwn import process
from utils.binary_utils import PLATFORM, RESOLVE_EXE
import os
import signal

from libdebug import debugger

logging.getLogger("pwnlib").setLevel(logging.ERROR)


match PLATFORM:
    case "amd64":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0x125E
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0x1261

        TEST_MULTITHREAD_ADDRESS = 0x128a
    case "aarch64":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0xa04
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0xa08

        TEST_MULTITHREAD_ADDRESS = 0xaec
    case "i386":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0x1251
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0x1255

        TEST_MULTITHREAD_ADDRESS = 0x1243
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")

class AttachDetachTest(unittest.TestCase):
    def test_attach(self):
        r = process(RESOLVE_EXE("attach_test"), env={})

        d = debugger()
        d.attach(r.pid)
        bp = d.breakpoint("printName", hardware=True)
        d.cont()

        r.recvuntil(b"name:")
        r.sendline(b"Io_no")

        self.assertTrue(d.instruction_pointer == bp.address)

        d.cont()

        d.kill()
        d.terminate()

        r.close()
        del r
        
    def test_attach_multithread(self):
        r = subprocess.Popen([RESOLVE_EXE("multithread_input")], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # Synchronize with the process to be sure that all threads have been created
        while b"All threads have been created." not in r.stdout.readline():
            pass
        
        d = debugger()
        d.attach(r.pid)
        
        # Breakpoint at the end of the thread function
        bp = d.breakpoint(TEST_MULTITHREAD_ADDRESS, hardware=True, callback=lambda _, __: _, file="binary")
        
        self.assertEqual(len(d.threads), 6)
        
        d.cont()
        
        for _ in range(5):
            r.stdin.write(b"1\n")
            r.stdin.flush()

        d.detach()
        r.kill()
        
        self.assertEqual(bp.hit_count, 5)

        d.terminate()

    def test_attach_and_detach_1(self):
        r = process(RESOLVE_EXE("attach_test"), env={})

        d = debugger()

        # Attach to the process
        d.attach(r.pid)
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        r.kill()
        d.terminate()

        r.close()
        del r

    def test_attach_and_detach_2(self):
        d = debugger(RESOLVE_EXE("attach_test"))

        # Run the process
        r = d.run()
        pid = d.pid
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        # kill the process
        os.kill(pid, signal.SIGKILL)
        d.terminate()

    def test_attach_and_detach_3(self):
        d = debugger(RESOLVE_EXE("attach_test"))

        r = d.run()
        pid = d.pid

        # We must ensure that any breakpoint is unset before detaching
        d.breakpoint(TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS, file="binary")
        d.breakpoint(TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS, hardware=True, file="binary")

        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        # kill the process
        os.kill(pid, signal.SIGKILL)
        d.terminate()

    def test_attach_and_detach_4(self):
        r = process(RESOLVE_EXE("attach_test"), env={})

        d = debugger()
        d.attach(r.pid)
        d.detach()
        
        # Validate that, after detaching, the process cannot be killed
        self.assertRaises(RuntimeError, d.kill)
        
        # Kill the process
        r.kill()
        d.terminate()

        r.close()
        del r
