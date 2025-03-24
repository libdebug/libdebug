#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase

import sys
import io
from libdebug import debugger

class CatchAllTest(TestCase):
    # We do not want to print the output of the test but we do want pprint_syscalls to be True to be sure that SIGTRAP is not caught
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__

    # Verify that debugging signals are properly filtered out by the status handler
    # before processing external signal handlers
    def test_catch_all(self):
        def catch_signal(t, ch):
            self.assertNotEqual(t.signal, "SIGTRAP")

        def dummy_syscall(t, h):
            pass
    
        def dummy_breakpoint(t, bp):
            pass

        def dummy_watchpoint(t, wp):
            pass

        d = debugger("/bin/ls")

        d.run()

        d.catch_signal("*", callback=catch_signal)
        d.handle_syscall("*", on_enter=dummy_syscall, on_exit=dummy_syscall)
        d.breakpoint("malloc", callback=dummy_breakpoint, file="libc.so.6")

        stack_map = d.maps.filter("stack")[0]

        good_stack_pos = stack_map.end - 0x20

        d.watchpoint(good_stack_pos, "rw", length=4, callback=dummy_watchpoint, file="absolute")
        d.pprint_syscalls = True

        d.cont()
        d.wait()

        d.terminate()
        
        