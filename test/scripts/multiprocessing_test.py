#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import PLATFORM, BASE, RESOLVE_EXE

from libdebug import debugger

match PLATFORM:
    case "amd64":
        # Address of the main after the fork
        AFTER_FORK = 0x12a3
    case "aarch64":
        # Address of the main after the fork
        AFTER_FORK = 0xb08
    case "i386":
        # Address of the main after the fork
        AFTER_FORK = 0x127f
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class MultiprocessingTest(TestCase):
    def test_multiprocessing_hw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_input"))
        
        r = d.run()

        # Breakpoint after the fork
        bp = d.bp(AFTER_FORK, file="binary", hardware=True)

        d.cont()
        
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 1)

        # Let take the child debugger and continue
        dd = d.children[0]
        dd.cont()
        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dd.wait()
        d.wait()

        d.kill()
        dd.kill()
        
    def test_multiprocessing_sw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_input"))
        
        r = d.run()

        # Breakpoint after the fork
        bp = d.bp(AFTER_FORK, file="binary", hardware=False)

        d.cont()
        
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 1)

        # Let take the child debugger and continue
        dd = d.children[0]
        dd.cont()
        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dd.wait()
        d.wait()

        d.kill()
        dd.kill()

       