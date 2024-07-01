#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import unittest

from libdebug import debugger


class SignalCatchTest(unittest.TestCase):
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

    def test_signal_catch_signal_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal(2, callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.cont()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

    def test_signal_pass_to_process(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

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

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_signal_disable_catch_signal(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        bp = d.breakpoint(0x12C4)

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

        # Uncatchering signals
        if bp.hit_on(d):
            catcher4.disable()
            catcher5.disable()
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 2)  # 1 times less because of the disable catch
        self.assertEqual(SIGPIPE_count, 2)  # 1 times less because of the disable catch

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_signal_unblock(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signals_to_block = [10, 15, 2, 3, 13]

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        bp = d.breakpoint(0x12C4)

        d.cont()

        # No block the signals anymore
        if bp.hit_on(d):
            d.signals_to_block = []

        d.cont()

        signal_received = []
        while True:
            try:
                signal_received.append(r.recvline())
            except RuntimeError:
                break

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

        self.assertEqual(signal_received[0], b"Received signal 3")
        self.assertEqual(signal_received[1], b"Received signal 13")
        self.assertEqual(signal_received[2], b"Exiting normally.")

        self.assertEqual(len(signal_received), 3)

    def test_signal_disable_catch_signal_unblock(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        d.signals_to_block = [10, 15, 2, 3, 13]

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        bp = d.breakpoint(0x12C4)

        d.cont()

        # No block the signals anymore
        if bp.hit_on(d):
            d.signals_to_block = []
            catcher4.disable()
            catcher5.disable()

        d.cont()

        signal_received = []
        while True:
            try:
                signal_received.append(r.recvline())
            except RuntimeError:
                break

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 2)  # 1 times less because of the disable catch
        self.assertEqual(SIGPIPE_count, 2)  # 1 times less because of the disable catch

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

        self.assertEqual(signal_received[0], b"Received signal 3")
        self.assertEqual(signal_received[1], b"Received signal 13")
        self.assertEqual(signal_received[2], b"Exiting normally.")

        self.assertEqual(len(signal_received), 3)

    def test_hijack_signal_with_catch_signal(self):
        def catcher_SIGUSR1(t, signal_number):
            # Hijack to SIGTERM
            t.signal = 15

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)

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

        self.assertEqual(catcher1.hit_count, 2)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hijack_signal_with_api(self):
        d = debugger("binaries/signal_handling_test")

        r = d.run()

        # Hijack to SIGTERM
        catcher1 = d.hijack_signal("SIGUSR1", 15)

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

        self.assertEqual(catcher1.hit_count, 2)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_recursive_true_with_catch_signal(self):
        SIGUSR1_count = 0
        SIGTERM_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            # Hijack to SIGTERM
            t.signal = 15

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1, recursive=True)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)

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

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_recursive_true_with_api(self):
        SIGTERM_count = 0

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.hijack_signal(10, 15, recursive=True)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)

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
        self.assertEqual(catcher1.hit_count, 2)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_recursive_false_with_catch_signal(self):
        SIGUSR1_count = 0
        SIGTERM_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count
            # Hijack to SIGTERM
            t.signal = 15

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1, recursive=False)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)

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
        self.assertEqual(SIGTERM_count, 2)  # 2 times in total because of the recursive=False

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_recursive_false_with_api(self):
        SIGTERM_count = 0

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.hijack_signal(10, 15, recursive=False)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)

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

        self.assertEqual(catcher1.hit_count, 2)
        self.assertEqual(SIGTERM_count, 2)  # 2 times in total because of the recursive=False
        self.assertEqual(SIGTERM_count, catcher2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 15" * 2)  # hijacked signal
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

    def test_hijack_signal_with_catch_signal_loop(self):
        # Let create a loop of hijacking signals

        def catcher_SIGUSR1(t, signal_number):
            # Hijack to SIGTERM
            t.signal = 15

        def catcher_SIGTERM(t, signal_number):
            # Hijack to SIGINT
            t.signal = 10

        d = debugger("binaries/signal_handling_test")

        d.run()

        d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1, recursive=True)
        d.catch_signal("SIGTERM", callback=catcher_SIGTERM, recursive=True)

        with self.assertRaises(RuntimeError):
            d.cont()
            d.kill()

        # Now we set recursive=False to avoid the loop
        d.run()

        d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1, recursive=False)
        d.catch_signal("SIGTERM", callback=catcher_SIGTERM)

        d.cont()
        d.kill()

        d.run()

        d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        d.catch_signal("SIGTERM", callback=catcher_SIGTERM, recursive=False)

        d.cont()
        d.kill()

        d.run()

        d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1, recursive=False)
        d.catch_signal("SIGTERM", callback=catcher_SIGTERM, recursive=False)

        d.cont()
        d.kill()

    def test_hijack_signal_with_api_loop(self):
        # Let create a loop of hijacking signals

        d = debugger("binaries/signal_handling_test")

        d.run()

        d.hijack_signal("SIGUSR1", "SIGTERM", recursive=True)
        d.hijack_signal(15, 10, recursive=True)

        with self.assertRaises(RuntimeError):
            d.cont()
            d.kill()

        # Now we set recursive=False to avoid the loop
        d.run()

        d.hijack_signal("SIGUSR1", "SIGTERM", recursive=False)
        d.hijack_signal(15, 10)

        d.cont()
        d.kill()

        d.run()

        d.hijack_signal("SIGUSR1", "SIGTERM")
        d.hijack_signal(15, 10, recursive=False)

        d.cont()
        d.kill()

        d.run()

        d.hijack_signal("SIGUSR1", "SIGTERM", recursive=False)
        d.hijack_signal(15, 10, recursive=False)

        d.cont()
        d.kill()

    def test_signal_unhijacking(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGTERM_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.hijack_signal("SIGQUIT", "SIGTERM", recursive=True)
        catcher5 = d.hijack_signal("SIGPIPE", "SIGTERM", recursive=True)

        bp = d.breakpoint(0x12C4)

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

        # Disable catching of signals
        if bp.hit_on(d):
            catcher4.disable()
            catcher5.disable()
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2 + 2 + 2)  # 2 times more because of the hijacking * 2 (SIGQUIT and SIGPIPE)
        self.assertEqual(SIGINT_count, 2)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 15" * 2 + b"Received signal 3")
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 13")

    def test_override_catch_signal(self):
        SIGPIPE_count_first = 0
        SIGPIPE_count_second = 0

        def catcher_SIGPIPE_first(t, signal_number):
            nonlocal SIGPIPE_count_first

            SIGPIPE_count_first += 1

        def catcher_SIGPIPE_second(t, signal_number):
            nonlocal SIGPIPE_count_second

            SIGPIPE_count_second += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE_first)

        bp = d.breakpoint(0x12C4)

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

        # Overriding the catcher
        if bp.hit_on(d):
            self.assertEqual(catcher1.hit_count, 2)
            catcher2 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE_second)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGPIPE_count_first, 2)
        self.assertEqual(SIGPIPE_count_second, 1)

        self.assertEqual(SIGPIPE_count_first, catcher1.hit_count)
        self.assertEqual(SIGPIPE_count_second, catcher2.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 13" * 3)

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count("has already been caught. Overriding it."),
            1,
        )

    def test_override_hijack(self):
        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.hijack_signal("SIGPIPE", 15)

        bp = d.breakpoint(0x12C4)

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

        # Overriding the catcher
        if bp.hit_on(d):
            self.assertEqual(catcher1.hit_count, 2)
            catcher2 = d.hijack_signal("SIGPIPE", "SIGINT")
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(catcher1.hit_count, 2)
        self.assertEqual(catcher2.hit_count, 1)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 2")

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count("has already been caught. Overriding it."),
            1,
        )

    def test_override_hybrid(self):
        SIGPIPE_count = 0

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.hijack_signal("SIGPIPE", 15)

        bp = d.breakpoint(0x12C4)

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

        # Overriding the catcher
        if bp.hit_on(d):
            self.assertEqual(catcher1.hit_count, 2)
            catcher2 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)
        d.cont()

        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(catcher1.hit_count, 2)
        self.assertEqual(catcher2.hit_count, 1)
        self.assertEqual(SIGPIPE_count, 1)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 2)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 3" * 3)
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 13")

        self.assertEqual(self.log_capture_string.getvalue().count("WARNING"), 1)
        self.assertEqual(
            self.log_capture_string.getvalue().count("has already been caught. Overriding it."),
            1,
        )

    def test_signal_get_signal(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            self.assertEqual(t.signal, "SIGUSR1")

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            self.assertEqual(t.signal, "SIGTERM")

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            self.assertEqual(t.signal, "SIGINT")

            SIGINT_count += 1

        def catcher_SIGQUIT(t, signal_number):
            nonlocal SIGQUIT_count

            self.assertEqual(t.signal, "SIGQUIT")

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, signal_number):
            nonlocal SIGPIPE_count

            self.assertEqual(t.signal, "SIGPIPE")

            SIGPIPE_count += 1

        d = debugger("binaries/signal_handling_test")

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal(2, callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.cont()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

    def test_signal_send_signal(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGTERM_count = 0

        def catcher_SIGUSR1(t, signal_number):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, signal_number):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, signal_number):
            nonlocal SIGINT_count

            SIGINT_count += 1

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.hijack_signal("SIGQUIT", "SIGTERM", recursive=True)
        catcher5 = d.hijack_signal("SIGPIPE", "SIGTERM", recursive=True)

        bp = d.breakpoint(0x12C4)

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

        # Uncatchering and send signals
        if bp.hit_on(d):
            catcher4.disable()
            catcher5.disable()
            d.signal = 10
        d.cont()

        SIGUSR1 += r.recvline()
        SIGQUIT += r.recvline()
        SIGPIPE += r.recvline()

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2 + 2 + 2)  # 2 times more because of the hijacking * 2 (SIGQUIT and SIGPIPE)
        self.assertEqual(SIGINT_count, 2)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10" * 3)
        self.assertEqual(SIGTERM, b"Received signal 15" * 2)
        self.assertEqual(SIGINT, b"Received signal 2" * 2)
        self.assertEqual(SIGQUIT, b"Received signal 15" * 2 + b"Received signal 3")
        self.assertEqual(SIGPIPE, b"Received signal 15" * 2 + b"Received signal 13")

    def test_signal_catch_sync_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        d = debugger("binaries/signal_handling_test")

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.run()

        catcher1 = d.catch_signal(10)
        catcher2 = d.catch_signal("SIGTERM")
        catcher3 = d.catch_signal(2)
        catcher4 = d.catch_signal("SIGQUIT")
        catcher5 = d.catch_signal("SIGPIPE")

        while not d.dead:
            d.cont()
            d.wait()
            if catcher1.hit_on(d):
                SIGUSR1_count += 1
            elif catcher2.hit_on(d):
                SIGTERM_count += 1
            elif catcher3.hit_on(d):
                SIGINT_count += 1
            elif catcher4.hit_on(d):
                SIGQUIT_count += 1
            elif catcher5.hit_on(d):
                SIGPIPE_count += 1

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

    def test_signal_catch_sync_pass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        signals = b""

        d = debugger("binaries/signal_handling_test")

        r = d.run()

        catcher1 = d.catch_signal(10)
        catcher2 = d.catch_signal("SIGTERM")
        catcher3 = d.catch_signal(2)
        catcher4 = d.catch_signal("SIGQUIT")
        catcher5 = d.catch_signal("SIGPIPE")

        signals = b""
        while not d.dead:
            d.cont()
            try:
                signals += r.recvline()
            except:
                pass
            d.wait()
            if catcher1.hit_on(d):
                SIGUSR1_count += 1
            elif catcher2.hit_on(d):
                SIGTERM_count += 1
            elif catcher3.hit_on(d):
                SIGINT_count += 1
            elif catcher4.hit_on(d):
                SIGQUIT_count += 1
            elif catcher5.hit_on(d):
                SIGPIPE_count += 1

        d.kill()

        self.assertEqual(SIGUSR1_count, 2)
        self.assertEqual(SIGTERM_count, 2)
        self.assertEqual(SIGINT_count, 2)
        self.assertEqual(SIGQUIT_count, 3)
        self.assertEqual(SIGPIPE_count, 3)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

        self.assertEqual(signals.count(b"Received signal 10"), 2)
        self.assertEqual(signals.count(b"Received signal 15"), 2)
        self.assertEqual(signals.count(b"Received signal 2"), 2)
        self.assertEqual(signals.count(b"Received signal 3"), 3)
        self.assertEqual(signals.count(b"Received signal 13"), 3)
