#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import unittest

from libdebug import debugger


class DeathTest(unittest.TestCase):
    def setUp(self):
        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self):
        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_handler.close()

    def test_io_death(self):
        d = debugger("binaries/segfault_test")

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Hello, World!")
        self.assertEqual(r.recvline(), b"Death is coming!")

        with self.assertRaises(RuntimeError):
            r.recvline()

        d.kill()

    def test_cont_death(self):
        d = debugger("binaries/segfault_test")

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Hello, World!")
        self.assertEqual(r.recvline(), b"Death is coming!")

        d.wait()

        with self.assertRaises(RuntimeError):
            d.cont()

        self.assertEqual(d.dead, True)
        self.assertEqual(d.threads[0].dead, True)

        d.kill()

    def test_instr_death(self):
        d = debugger("binaries/segfault_test", aslr=False)

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Hello, World!")
        self.assertEqual(r.recvline(), b"Death is coming!")

        d.wait()

        self.assertEqual(d.regs.pc, 0xaaaaaaaa0784)

        d.kill()

    def test_exit_signal_death(self):
        d = debugger("binaries/segfault_test")

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Hello, World!")
        self.assertEqual(r.recvline(), b"Death is coming!")

        d.wait()

        self.assertEqual(d.exit_signal, "SIGSEGV")
        self.assertEqual(d.exit_signal, d.threads[0].exit_signal)

        d.kill()

    def test_exit_code_death(self):
        d = debugger("binaries/segfault_test")

        r = d.run()

        d.cont()

        self.assertEqual(r.recvline(), b"Hello, World!")
        self.assertEqual(r.recvline(), b"Death is coming!")

        d.wait()

        d.exit_code

        self.assertEqual(
            self.log_capture_string.getvalue().count("No exit code available."),
            1,
        )

        d.kill()

    def test_exit_code_normal(self):
        d = debugger("binaries/basic_test")

        d.run()

        d.cont()

        d.wait()

        self.assertEqual(d.exit_code, 0)

        d.exit_signal

        self.assertEqual(
            self.log_capture_string.getvalue().count("No exit signal available."),
            1,
        )

        d.kill()

    def test_post_mortem_after_kill(self):
        d = debugger("binaries/basic_test")

        d.run()

        d.cont()

        d.interrupt()
        d.kill()

        # We should be able to access the registers also after the process has been killed
        d.regs.x0
        d.regs.x1
        d.regs.x2
