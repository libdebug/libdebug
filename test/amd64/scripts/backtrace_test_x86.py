#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BacktraceTestX86(unittest.TestCase):
    def test_backtrace(self):
        d = debugger("binaries/backtrace_test_x86")

        d.run()

        bp0 = d.breakpoint("main+e")
        bp1 = d.breakpoint("function1+6")
        bp2 = d.breakpoint("function2+6")
        bp3 = d.breakpoint("function3+6")
        bp4 = d.breakpoint("function4+6")
        bp5 = d.breakpoint("function5+6")
        bp6 = d.breakpoint("function6+6")

        d.cont()

        self.assertTrue(d.eip == bp0.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace, ["main+e"])

        d.cont()

        self.assertTrue(d.eip == bp1.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:2], ["function1+6", "main+16"])

        d.cont()

        self.assertTrue(d.eip == bp2.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(backtrace[:3], ["function2+6", "function1+10", "main+16"])

        d.cont()

        self.assertTrue(d.eip == bp3.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:4], ["function3+6", "function2+15", "function1+10", "main+16"]
        )

        d.cont()

        self.assertTrue(d.eip == bp4.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:5],
            ["function4+6", "function3+15", "function2+15", "function1+10", "main+16"],
        )

        d.cont()

        self.assertTrue(d.eip == bp5.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:6],
            [
                "function5+6",
                "function4+15",
                "function3+15",
                "function2+15",
                "function1+10",
                "main+16",
            ],
        )

        d.cont()

        self.assertTrue(d.eip == bp6.address)
        backtrace = d.backtrace()
        self.assertIn("_start", backtrace.pop())
        self.assertEqual(
            backtrace[:7],
            [
                "function6+6",
                "function5+15",
                "function4+15",
                "function3+15",
                "function2+15",
                "function1+10",
                "main+16",
            ],
        )

        d.kill()


if __name__ == "__main__":
    unittest.main()
