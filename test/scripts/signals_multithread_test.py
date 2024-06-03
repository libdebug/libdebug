#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class SignalMultithreadTest(unittest.TestCase):
    def test_signal_multithread_undet_hook(self):
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

        d = debugger("binaries/signals_multithread_undet_test")

        r = d.run()

        hook1 = d.hook_signal(10, callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal(2, callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        r.sendline(b"sync")
        r.sendline(b"sync")

        # Receive the exit message
        r.recvline(2)

        d.kill()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

    def test_signal_multithread_undet_pass(self):
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

        d = debugger("binaries/signals_multithread_undet_test")

        r = d.run()

        d.signal_to_pass = ["SIGUSR1", 15, "SIGINT", 3, 13]

        hook1 = d.hook_signal("SIGUSR1", callback=hook_SIGUSR1)
        hook2 = d.hook_signal("SIGTERM", callback=hook_SIGTERM)
        hook3 = d.hook_signal("SIGINT", callback=hook_SIGINT)
        hook4 = d.hook_signal("SIGQUIT", callback=hook_SIGQUIT)
        hook5 = d.hook_signal("SIGPIPE", callback=hook_SIGPIPE)

        d.cont()

        received = []
        for _ in range(24):
            received.append(r.recvline())

        r.sendline(b"sync")
        r.sendline(b"sync")

        received.append(r.recvline())
        received.append(r.recvline())

        d.kill()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, hook1.hit_count)
        self.assertEqual(SIGTERM_count, hook2.hit_count)
        self.assertEqual(SIGINT_count, hook3.hit_count)
        self.assertEqual(SIGQUIT_count, hook4.hit_count)
        self.assertEqual(SIGPIPE_count, hook5.hit_count)

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal 10"), 4)
        self.assertEqual(received.count(b"Received signal 15"), 4)
        self.assertEqual(received.count(b"Received signal 2"), 4)
        self.assertEqual(received.count(b"Received signal 3"), 6)
        self.assertEqual(received.count(b"Received signal 13"), 6)
        # Note: sometimes the signals are passed to ptrace once and received twice
        # Maybe another ptrace/kernel/whatever problem in multithreaded programs (?)
        # Using raise(sig) instead of kill(pid, sig) to send signals in the original
        # program seems to mitigate the problem for whatever reason
        # I will investigate this further in the future, but for now this is fine
