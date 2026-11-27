#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import random

from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE
from libdebug import debugger


class ConditionalRecvTest(TestCase):
    def test_conditional_recv(self) -> None:
        d = debugger(RESOLVE_EXE("conditional_recv_test"))

        for i in range(25):
            pipe = d.run()
            bp = d.breakpoint("break_here", hardware=True, file="binary") # End of main
            d.cont()

            drop = (random.randint(0, 1) == 1)

            patterns = [
                b"Breathe!",
                b"Sunflower.",
                b"Rainbow.",
                b"Three to the right.",
                b"Four to the left.",
                b"450",
                b"This should never happen!"
            ]

            index, out = pipe.match_recvuntil(patterns, drop=drop)
            d.wait()

            self.assertTrue(bp.hit_on(d))

            cond_mem_bytes = d.memory["condition", 4, "binary"]
            cond_mem_int = int.from_bytes(cond_mem_bytes, byteorder="little", signed=True)

            self.assertEqual(index + 1, cond_mem_int)
            self.assertNotEqual(index + 1, 7)  # "This should never happen!"

            additional = (patterns[index] if not drop else b"")
            self.assertEqual(out, b"Conditional receive test program\n" + additional)
            d.kill()

        d.terminate()

    def test_conditional_recv_stderr(self) -> None:
        d = debugger([RESOLVE_EXE("conditional_recv_test"), "stderr"])

        for i in range(25):
            pipe = d.run()
            bp = d.breakpoint("break_here", hardware=True, file="binary") # End of main
            d.cont()

            drop = (random.randint(0, 1) == 1)

            patterns = [
                b"Breathe!",
                b"Sunflower.",
                b"Rainbow.",
                b"Three to the right.",
                b"Four to the left.",
                b"450",
                b"This should never happen!"
            ]

            index, out = pipe.match_recverruntil(patterns, drop=drop)
            d.wait()

            self.assertTrue(bp.hit_on(d))

            cond_mem_bytes = d.memory["condition", 4, "binary"]
            cond_mem_int = int.from_bytes(cond_mem_bytes, byteorder="little", signed=True)

            self.assertEqual(index + 1, cond_mem_int)
            self.assertNotEqual(index + 1, 7)  # "This should never happen!"

            additional = (patterns[index] if not drop else b"")
            self.assertEqual(out, additional)
            d.kill()

        d.terminate()

    def test_conditional_recv_wrong_call(self) -> None:
        d = debugger(RESOLVE_EXE("conditional_recv_test"))

        pipe = d.run()
        d.cont()

        with self.assertRaises(ValueError):
            pipe.match_recvuntil([])

        with self.assertRaises(ValueError):
            pipe.match_recvuntil([0.5, {"a" : 2}], drop=True)

        d.terminate()