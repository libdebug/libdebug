#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


class BacktraceTest(TestCase):
    def setUp(self):
        self.d = debugger(RESOLVE_EXE("backtrace_test"), aslr=False)

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
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

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
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

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_backtrace_as_symbols_aarch64(self):
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

        self.assertTrue(d.regs.pc == bp0.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:1], ["main+8"])

        d.cont()

        self.assertTrue(d.regs.pc == bp1.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+8", "main+c"])

        d.cont()

        self.assertTrue(d.regs.pc == bp2.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+8", "function1+10", "main+c"])

        d.cont()

        self.assertTrue(d.regs.pc == bp3.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+8", "function2+18", "function1+10", "main+c"]
        )

        d.cont()

        self.assertTrue(d.regs.pc == bp4.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+8", "function3+18", "function2+18", "function1+10", "main+c"],
        )

        d.cont()

        self.assertTrue(d.regs.pc == bp5.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:6],
            [
                "function5+8",
                "function4+18",
                "function3+18",
                "function2+18",
                "function1+10",
                "main+c",
            ],
        )

        d.cont()

        self.assertTrue(d.regs.pc == bp6.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:7],
            [
                "function6+8",
                "function5+18",
                "function4+18",
                "function3+18",
                "function2+18",
                "function1+10",
                "main+c",
            ],
        )

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_backtrace_aarch64(self):
        # TODO
        pass

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_backtrace_as_symbols_i386(self):
        d = self.d

        d.run()

        bp0 = d.breakpoint("main+e")
        bp1 = d.breakpoint("function1+9")
        bp2 = d.breakpoint("function2+9")
        bp3 = d.breakpoint("function3+9")
        bp4 = d.breakpoint("function4+9")
        bp5 = d.breakpoint("function5+9")
        bp6 = d.breakpoint("function6+9")

        d.cont()

        self.assertTrue(d.regs.eip == bp0.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:1], ["main+e"])

        d.cont()

        self.assertTrue(d.regs.eip == bp1.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+9", "main+16"])

        d.cont()

        self.assertTrue(d.regs.eip == bp2.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+9", "function1+10", "main+16"])

        d.cont()

        self.assertTrue(d.regs.eip == bp3.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+9", "function2+15", "function1+10", "main+16"]
        )

        d.cont()

        self.assertTrue(d.regs.eip == bp4.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+9", "function3+15", "function2+15", "function1+10", "main+16"],
        )

        d.cont()

        self.assertTrue(d.regs.eip == bp5.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:6],
            [
                "function5+9",
                "function4+15",
                "function3+15",
                "function2+15",
                "function1+10",
                "main+16",
            ],
        )

        d.cont()

        self.assertTrue(d.regs.eip == bp6.address)
        backtrace = d.backtrace(as_symbols=True)
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:7],
            [
                "function6+9",
                "function5+15",
                "function4+15",
                "function3+15",
                "function2+15",
                "function1+10",
                "main+16",
            ],
        )

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_backtrace_i386(self):
        d = self.d

        d.run()

        bp0 = d.breakpoint("main+e")
        bp1 = d.breakpoint("function1+9")
        bp2 = d.breakpoint("function2+9")
        bp3 = d.breakpoint("function3+9")
        bp4 = d.breakpoint("function4+9")
        bp5 = d.breakpoint("function5+9")
        bp6 = d.breakpoint("function6+9")

        d.cont()

        self.assertTrue(d.regs.eip == bp0.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:1], [0x8049174])

        d.cont()

        self.assertTrue(d.regs.eip == bp1.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:2], [0x80491a8, 0x804917c])

        d.cont()

        self.assertTrue(d.regs.eip == bp2.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:3], [0x80491bd, 0x80491af, 0x804917c])

        d.cont()

        self.assertTrue(d.regs.eip == bp3.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(backtrace[:4], [0x80491d7, 0x80491c9, 0x80491af, 0x804917c])

        d.cont()

        self.assertTrue(d.regs.eip == bp4.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:5], [0x80491f1, 0x80491e3, 0x80491c9, 0x80491af, 0x804917c]
        )

        d.cont()

        self.assertTrue(d.regs.eip == bp5.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:6], [0x804920b, 0x80491fd, 0x80491e3, 0x80491c9, 0x80491af, 0x804917c]
        )

        d.cont()

        self.assertTrue(d.regs.eip == bp6.address)
        backtrace = d.backtrace()
        backtrace.pop()
        self.assertEqual(
            backtrace[:7],
            [
                0x8049225,
                0x8049217,
                0x80491fd,
                0x80491e3,
                0x80491c9,
                0x80491af,
                0x804917c,
            ],
        )

        d.kill()
        d.terminate()
