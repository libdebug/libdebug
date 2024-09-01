#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


class BacktraceTest(TestCase):
    def setUp(self):
        self.d = debugger(RESOLVE_EXE("backtrace_test"))

    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_backtrace_as_symbols_amd64(self):
        d = self.d

        d.run()

        bp0 = d.breakpoint("main+8")
        bp1 = d.breakpoint("function1+8")
        bp2 = d.breakpoint("function2+8")
        bp3 = d.breakpoint("function3+8")
        bp4 = d.breakpoint("function4+8")
        bp5 = d.breakpoint("function5+8")
        bp6 = d.breakpoint("function6+8")

        d.cont()

        self.assertTrue(d.regs.rip == bp0.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:1], ["main+8"])

        d.cont()

        self.assertTrue(d.regs.rip == bp1.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+8", "main+16"])

        d.cont()

        self.assertTrue(d.regs.rip == bp2.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+8", "function1+12", "main+16"])

        d.cont()

        self.assertTrue(d.regs.rip == bp3.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+8", "function2+1c", "function1+12", "main+16"]
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp4.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+8", "function3+1c", "function2+1c", "function1+12", "main+16"],
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp5.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:6],
            [
                "function5+8",
                "function4+1c",
                "function3+1c",
                "function2+1c",
                "function1+12",
                "main+16",
            ],
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp6.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:7],
            [
                "function6+8",
                "function5+1c",
                "function4+1c",
                "function3+1c",
                "function2+1c",
                "function1+12",
                "main+16",
            ],
        )

        d.kill()
        d.terminate()

    @skipUnless(libcontext.platform == "amd64", "Requires amd64")
    def test_backtrace_amd64(self):
        d = self.d

        d.run()

        bp0 = d.breakpoint("main+8")
        bp1 = d.breakpoint("function1+8")
        bp2 = d.breakpoint("function2+8")
        bp3 = d.breakpoint("function3+8")
        bp4 = d.breakpoint("function4+8")
        bp5 = d.breakpoint("function5+8")
        bp6 = d.breakpoint("function6+8")

        d.cont()

        self.assertTrue(d.regs.rip == bp0.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:1], [0x555555555151])

        d.cont()

        self.assertTrue(d.regs.rip == bp1.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:2], [0x55555555518a, 0x55555555515f])

        d.cont()

        self.assertTrue(d.regs.rip == bp2.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:3], [0x55555555519e, 0x555555555194, 0x55555555515f])

        d.cont()

        self.assertTrue(d.regs.rip == bp3.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:4], [0x5555555551bc, 0x5555555551b2, 0x555555555194, 0x55555555515f]
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp4.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:5],
            [0x5555555551da, 0x5555555551d0, 0x5555555551b2, 0x555555555194, 0x55555555515f],
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp5.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:6],
            [
                0x5555555551f8,
                0x5555555551ee,
                0x5555555551d0,
                0x5555555551b2,
                0x555555555194,
                0x55555555515f,
            ],
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp6.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:7],
            [
                0x555555555216,
                0x55555555520c,
                0x5555555551ee,
                0x5555555551d0,
                0x5555555551b2,
                0x555555555194,
                0x55555555515f,
            ],
        )

        d.kill()
        d.terminate()
