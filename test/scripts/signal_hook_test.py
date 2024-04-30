#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import os
import sys
import unittest

from libdebug import debugger


class SignalHookTest(unittest.TestCase):
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

    def test_signal_hooking(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        d.run()

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal(2, callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

    def test_signal_pass_to_process(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_signal_unhooking(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = [10, 15, 2, 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # Unhooking signals
        if bp.hit_on:
            d.unhook_signal(hook4)
            d.unhook_signal(hook5)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 2)  # 1 times less because of the unhooking
        self.assertEqual(SIGPIPE_count, 2)  # 1 times less because of the unhooking

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_signal_unpass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = [10, 15, 2, 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # No pass the signals to the process anymore
        if bp.hit_on:
            d.signal_to_pass = []

        d.cont()

        # If not passed, the process will not receive any signal and not print any message
        exiting = r.recvline()
        self.assertRaises(TimeoutError, r.recvline, timeout=1)

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 2)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 2)
        self.assertEqual(exiting, b"Exiting normally.")

    def test_signal_unhook_unpass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def hook_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = [10, 15, 2, 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # No pass the signals to the process anymore
        if bp.hit_on:
            d.signal_to_pass = []
            d.unhook_signal(hook4)
            d.unhook_signal(hook5)

        d.cont()

        # If not passed, the process will not receive any signal and not print any message
        exiting = r.recvline()
        self.assertRaises(TimeoutError, r.recvline, timeout=1)

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 2)  # 1 times less because of the unhooking
        self.assertEqual(SIGPIPE_count, 2)  # 1 times less because of the unhooking

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 2)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 2)
        self.assertEqual(exiting, b"Exiting normally.")

        # We expect two warnings, one for each unmanaged signal (not passed, not hooked)
        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 2)

    def test_force_continue_true(self):
        # force_continue=True will make the debugger to continue the process even if there are unmanaged signals
        d = debugger("binaries/signal_handling_test", force_continue=True)

        r = d.run()

        # We do not hook or pass any signal

        d.cont()

        exiting = r.recvline()
        self.assertEqual(exiting, b"Exiting normally.")

        # If not passed, the process will not receive any signal and not print any message
        self.assertRaises(TimeoutError, r.recvline, timeout=1)

        d.kill()

        # We expect 12 warnings, one for each unmanaged signal (not passed, not hooked)
        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 12)
        self.assertEqual(
            self.log_capture_string.getvalue().count(
                "Stop due to unhandled signal. Trying to continue."
            ),
            12,
        )

    def test_force_continue_false(self):
        # force_continue=False will make the debugger to stop the process if there are unmanaged signals
        d = debugger("binaries/signal_handling_test", force_continue=False)

        r = d.run()

        # We do not hook or pass any signal

        d.cont()

        # We expect 12 warnings, one for each unmanaged signal (not passed, not hooked)

        for i in range(1, 13):
            d.wait()
            self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), i)
            self.assertEqual(
                self.log_capture_string.getvalue().count(
                    "Stop due to unhandled signal. Hanging."
                ),
                i,
            )
            d.cont()

        exiting = r.recvline()
        self.assertEqual(exiting, b"Exiting normally.")

        # If not passed, the process will not receive any signal and not print any message
        self.assertRaises(TimeoutError, r.recvline, timeout=1)

        d.kill()

    def test_hijack_signal_with_hooking(self):
        def hook_SIGUSR1(t, signal_number):
            # Hijack to SIGTERM
            t.signal_number = 15

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(hook1.hit_count, 2)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hijack_signal_with_api(self):
        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        # Hijack to SIGTERM
        hook1 = d.hijack_signal("SIGUSR1", 15)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(hook1.hit_count, 2)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hook_hijack_true_with_hook(self):
        SIGUSR1_count = 0
        SIGTERM_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            # Hijack to SIGTERM
            t.signal_number = 15

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1, hook_hijack=True)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 4)  # 2 times more because of the hijack

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hook_hijack_true_with_api(self):
        SIGTERM_count = 0

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hijack_signal(10, 15, hook_hijack=True)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGTERM_count, 4)  # 2 times more because of the hijack
        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(SIGTERM_count, hook2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hook_hijack_false_with_hook(self):
        SIGUSR1_count = 0
        SIGTERM_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            # Hijack to SIGTERM
            t.signal_number = 15

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1, hook_hijack=False)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(
            SIGTERM_count, 2
        )  # 2 times in total because of the hook_hijack=False

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hook_hijack_false_with_api(self):
        SIGTERM_count = 0

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hijack_signal(10, 15, hook_hijack=False)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(
            SIGTERM_count, 2
        )  # 2 times in total because of the hook_hijack=False
        self.assertEqual(SIGTERM_count, hook2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hijack_signal_with_hooking_loop(self):
        # Let create a loop of hijacking signals

        def hook_SIGUSR1(t, signal_number):
            # Hijack to SIGTERM
            t.signal_number = 15

        def hook_SIGTERM(t, signal_number):
            # Hijack to SIGINT
            t.signal_number = 10

        d = debugger("binaries/signal_handling_test")

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        with self.assertRaises(RuntimeError):
            d.cont()
            d.kill()

        # Now we set hook_hijack=False to avoid the loop
        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hook_signal("SIGUSR1", callback=hook_SIGUSR1, hook_hijack=False)
        d.hook_signal("SIGTERM", callback=hook_SIGTERM)

        d.cont()
        d.kill()

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        d.hook_signal("SIGTERM", callback=hook_SIGTERM, hook_hijack=False)

        d.cont()
        d.kill()

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hook_signal("SIGUSR1", callback=hook_SIGUSR1, hook_hijack=False)
        d.hook_signal("SIGTERM", callback=hook_SIGTERM, hook_hijack=False)

        d.cont()
        d.kill()

    def test_hijack_signal_with_api_loop(self):
        # Let create a loop of hijacking signals

        d = debugger("binaries/signal_handling_test")

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hijack_signal("SIGUSR1", "SIGTERM")
        d.hijack_signal(15, 10)

        with self.assertRaises(RuntimeError):
            d.cont()
            d.kill()

        # Now we set hook_hijack=False to avoid the loop
        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hijack_signal("SIGUSR1", "SIGTERM", hook_hijack=False)
        d.hijack_signal(15, 10)

        d.cont()
        d.kill()

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hijack_signal("SIGUSR1", "SIGTERM")
        d.hijack_signal(15, 10, hook_hijack=False)

        d.cont()
        d.kill()

        d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.hijack_signal("SIGUSR1", "SIGTERM", hook_hijack=False)
        d.hijack_signal(15, 10, hook_hijack=False)

        d.cont()
        d.kill()

    def test_signal_unhijacking(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGTERM_count = 0

        def hook_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def hook_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def hook_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = [10, 15, 2, 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hijack_signal("SIGQUIT", "SIGTERM")
        hook5 = d.hijack_signal("SIGPIPE", "SIGTERM")

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # Unhooking signals
        if bp.hit_on:
            d.unhook_signal(hook4)
            d.unhook_signal(hook5)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(
            SIGTERM_count, 2 + 2 + 2
        )  # 2 times more because of the hijacking * 2 (SIGQUIT and SIGPIPE)
        self.assertEqual(SIGINT_count, 2)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 15" * 2 + b"Received signal 3")
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 13")

    def test_override_hook(self):
        SIGPIPE_count_first = 0
        SIGPIPE_count_second = 0

        def hook_SIGPIPE_first(t, signal_number):
            nonlocal SIGPIPE_count_first

            SIGPIPE_count_first += 1

        def hook_SIGPIPE_second(t, signal_number):
            nonlocal SIGPIPE_count_second

            SIGPIPE_count_second += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE_first)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # Overriding the hook
        if bp.hit_on:
            self.assertEqual(hook1.hit_count, 2)
            hook2 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE_second)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGPIPE_count_first, 2)
        self.assertEqual(SIGPIPE_count_second, 1)

        self.assertEqual(SIGPIPE_count_first, hook1.hit_count)
        self.assertEqual(SIGPIPE_count_second, hook2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count(
                "is already hooked. Overriding it."
            ),
            1,
        )

    def test_override_hijack(self):
        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hijack_signal("SIGPIPE", 15)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # Overriding the hook
        if bp.hit_on:
            self.assertEqual(hook1.hit_count, 2)
            hook2 = d.hijack_signal("SIGPIPE", "SIGINT")
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 2")

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count(
                "is already hooked. Overriding it."
            ),
            1,
        )

    def test_override_hybrid(self):
        SIGPIPE_count = 0

        def hook_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hijack_signal("SIGPIPE", 15)

        bp = d.breakpoint(0x1312)

        d.cont()

        SIGUSR1 = r.recvline()
        SIGTERM = r.recvline()
        SIGINT = r.recvline()
        SIGQUIT = r.recvline()
        SIGPIPE = r.recvline()

        SIGUSR1 += r.recvline()
        SIGTERM += r.recvline()
        SIGINT += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        # Overriding the hook
        if bp.hit_on:
            self.assertEqual(hook1.hit_count, 2)
            hook2 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(hook1.hit_count, 2)
        self.assertEqual(hook2.hit_count, 1)
        self.assertEqual(SIGPIPE_count, 1)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 13")

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count(
                "is already hooked. Overriding it."
            ),
            1,
        )
