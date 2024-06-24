#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BacktraceTest(unittest.TestCase):
    def setUp(self):
        self.d = debugger("binaries/backtrace_test")

    def test_backtrace(self):
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
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:1], ["main+8"])

        d.cont()

        self.assertTrue(d.regs.rip == bp1.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+8", "main+16"])

        d.cont()

        self.assertTrue(d.regs.rip == bp2.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+8", "function1+12", "main+16"])

        d.cont()

        self.assertTrue(d.regs.rip == bp3.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+8", "function2+1c", "function1+12", "main+16"]
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp4.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+8", "function3+1c", "function2+1c", "function1+12", "main+16"],
        )

        d.cont()

        self.assertTrue(d.regs.rip == bp5.address)
        backtrace = d.backtrace()
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
        backtrace = d.backtrace()
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


if __name__ == "__main__":
    unittest.main()
