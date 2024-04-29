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

        r = d.run()

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        d.kill()

        self.assertEqual(SIGUSR1_count, 1)
        self.assertEqual(SIGTERM_count, 1)
        self.assertEqual(SIGINT_count, 1)
        self.assertEqual(SIGQUIT_count, 1)
        self.assertEqual(SIGPIPE_count, 1)

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
        
        d.signal_to_pass = [10, 15, 2, 3, 13]

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

        d.kill()

        self.assertEqual(SIGUSR1_count, 1)
        self.assertEqual(SIGTERM_count, 1)
        self.assertEqual(SIGINT_count, 1)
        self.assertEqual(SIGQUIT_count, 1)
        self.assertEqual(SIGPIPE_count, 1)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        self.assertEqual(SIGUSR1, b"Received signal 10")
        self.assertEqual(SIGTERM, b"Received signal 15")
        self.assertEqual(SIGINT, b"Received signal 2")
        self.assertEqual(SIGQUIT, b"Received signal 3")
        self.assertEqual(SIGPIPE, b"Received signal 13")
