#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import logging
import unittest

from pwn import process
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext

logging.getLogger("pwnlib").setLevel(logging.ERROR)


match libcontext.platform:
    case "amd64":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0x125E
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0x1261
    case "aarch64":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0xa04
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0xa08
    case "i386":
        TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS = 0x1251
        TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS = 0x1255
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")

class AttachDetachTest(unittest.TestCase):
    def test_attach(self):
        r = process(RESOLVE_EXE("attach_test"))

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

    def test_attach_and_detach_1(self):
        r = process(RESOLVE_EXE("attach_test"))

        d = debugger()

        # Attach to the process
        d.attach(r.pid)
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        r.kill()
        d.terminate()

    def test_attach_and_detach_2(self):
        d = debugger(RESOLVE_EXE("attach_test"))

        # Run the process
        r = d.run()
        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        d.kill()
        d.terminate()

    def test_attach_and_detach_3(self):
        d = debugger(RESOLVE_EXE("attach_test"))

        r = d.run()

        # We must ensure that any breakpoint is unset before detaching
        d.breakpoint(TEST_ATTACH_AND_DETACH_3_BP1_ADDRESS, file="binary")
        d.breakpoint(TEST_ATTACH_AND_DETACH_3_BP2_ADDRESS, hardware=True, file="binary")

        d.detach()

        # Validate that, after detaching, the process is still running
        r.recvuntil(b"name:", timeout=1)
        r.sendline(b"Io_no")

        d.kill()
        d.terminate()

    def test_attach_and_detach_4(self):
        r = process(RESOLVE_EXE("attach_test"))

        d = debugger()
        d.attach(r.pid)
        d.detach()
        d.kill()

        # Validate that, after detaching and killing, the process is effectively terminated
        self.assertRaises(EOFError, r.sendline, b"provola")

        d.terminate()
