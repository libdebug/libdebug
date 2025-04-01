#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class CorruptedELFTest(TestCase):
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

    def test_basic_corrupted_elf(self):
        d = debugger(RESOLVE_EXE("corrupted_elf_test"))

        r = d.run()

        # We hijack SIGBUS to SIGCONT to avoid the process to terminate
        hijacker = d.hijack_signal("SIGBUS", "SIGCONT")

        hit = False

        def on_enter_1337(_, __):
            nonlocal hit
            hit = True

        # We check that we can still handle syscalls
        handler = d.handle_syscall(0x1337, on_enter=on_enter_1337)

        d.cont()

        # We ensure that pipes work
        self.assertEqual(r.recvline(), b"Provola!")

        r.sendline(b"3")

        d.kill()
        d.terminate()

        self.assertTrue(hit)
        self.assertEqual(hijacker.hit_count, 1)
        self.assertEqual(handler.hit_count, 1)

        # Validate that we triggered a few warnings
        capture = self.log_capture_string.getvalue()
        self.assertIn("Failed to get the architecture of the binary:", capture)
        self.assertIn("Failed to get the entry point for the given binary:", capture)

    def test_symbol_access_corrupted_elf(self):
        d = debugger(RESOLVE_EXE("corrupted_elf_test"))
        d.run()

        with self.assertRaises(ValueError):
            # This should raise an exception, because the symbol is in the corrupted executable
            d.bp("skill_issue")

        # This should not raise an exception, it just wont contain any symbol from the executable
        d.symbols

        d.kill()
        d.terminate()

        # Validate that we triggered a few warnings
        capture = self.log_capture_string.getvalue()
        self.assertIn("Failed to get the architecture of the binary:", capture)
        self.assertIn("Failed to get the entry point for the given binary:", capture)
