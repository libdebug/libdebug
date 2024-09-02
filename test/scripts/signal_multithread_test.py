#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match libcontext.platform:
    case "amd64":
        TEST_SIGNAL_MULTITHREAD_SEND_SIGNAL_BP_ADDRESS = 0x14d8
    case "aarch64":
        TEST_SIGNAL_MULTITHREAD_SEND_SIGNAL_BP_ADDRESS = 0xf1c
    case _:
        raise NotImplementedError(f"Platform {libcontext.platform} not supported by this test")

class SignalMultithreadTest(TestCase):
    def test_signal_multithread_undet_catch_signal_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, sc):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, sc):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, sc):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, sc):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, sc):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger(RESOLVE_EXE("signals_multithread_undet_test"))

        r = d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal(2, callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.cont()

        r.sendline(b"sync")
        r.sendline(b"sync")

        # Receive the exit message
        r.recvline(2)

        d.kill()
        d.terminate()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

    def test_signal_multithread_undet_pass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0

        def catcher_SIGUSR1(t, sc):
            nonlocal SIGUSR1_count

            SIGUSR1_count += 1

        def catcher_SIGTERM(t, sc):
            nonlocal SIGTERM_count

            SIGTERM_count += 1

        def catcher_SIGINT(t, sc):
            nonlocal SIGINT_count

            SIGINT_count += 1

        def catcher_SIGQUIT(t, sc):
            nonlocal SIGQUIT_count

            SIGQUIT_count += 1

        def catcher_SIGPIPE(t, sc):
            nonlocal SIGPIPE_count

            SIGPIPE_count += 1

        d = debugger(RESOLVE_EXE("signals_multithread_undet_test"))

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.cont()

        received = []
        for _ in range(24):
            received.append(r.recvline())

        r.sendline(b"sync")
        r.sendline(b"sync")

        received.append(r.recvline())
        received.append(r.recvline())

        d.kill()
        d.terminate()

        self.assertEqual(SIGUSR1_count, 4)
        self.assertEqual(SIGTERM_count, 4)
        self.assertEqual(SIGINT_count, 4)
        self.assertEqual(SIGQUIT_count, 6)
        self.assertEqual(SIGPIPE_count, 6)

        self.assertEqual(SIGUSR1_count, catcher1.hit_count)
        self.assertEqual(SIGTERM_count, catcher2.hit_count)
        self.assertEqual(SIGINT_count, catcher3.hit_count)
        self.assertEqual(SIGQUIT_count, catcher4.hit_count)
        self.assertEqual(SIGPIPE_count, catcher5.hit_count)

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

    def test_signal_multithread_det_catch_signal_block(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def catcher_SIGUSR1(t, sc):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def catcher_SIGTERM(t, sc):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def catcher_SIGINT(t, sc):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGQUIT(t, sc):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGPIPE(t, sc):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger(RESOLVE_EXE("signals_multithread_det_test"))

        r = d.run()

        catcher1 = d.catch_signal(10, callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal(2, callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.signals_to_block = ["SIGUSR1", 15, "SIGINT", 3, 13]

        d.cont()

        # Receive the exit message
        r.recvline(timeout=15)
        r.sendline(b"sync")
        r.recvline()

        receiver = d.threads[1].thread_id
        d.kill()
        d.terminate()

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

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)

    def test_signal_multithread_det_pass(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def catcher_SIGUSR1(t, sc):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def catcher_SIGTERM(t, sc):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def catcher_SIGINT(t, sc):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGQUIT(t, sc):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGPIPE(t, sc):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger(RESOLVE_EXE("signals_multithread_det_test"))

        r = d.run()

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.cont()

        received = []
        for _ in range(13):
            received.append(r.recvline(timeout=5))

        r.sendline(b"sync")
        received.append(r.recvline(timeout=5))

        receiver = d.threads[1].thread_id
        d.kill()
        d.terminate()

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

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal on receiver 10"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 15"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 2"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 3"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 13"), 3)

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)

    def test_signal_multithread_send_signal(self):
        SIGUSR1_count = 0
        SIGINT_count = 0
        SIGQUIT_count = 0
        SIGTERM_count = 0
        SIGPIPE_count = 0
        tids = []

        def catcher_SIGUSR1(t, sc):
            nonlocal SIGUSR1_count
            nonlocal tids

            SIGUSR1_count += 1
            tids.append(t.thread_id)

        def catcher_SIGTERM(t, sc):
            nonlocal SIGTERM_count
            nonlocal tids

            SIGTERM_count += 1
            tids.append(t.thread_id)

        def catcher_SIGINT(t, sc):
            nonlocal SIGINT_count
            nonlocal tids

            SIGINT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGQUIT(t, sc):
            nonlocal SIGQUIT_count
            nonlocal tids

            SIGQUIT_count += 1
            tids.append(t.thread_id)

        def catcher_SIGPIPE(t, sc):
            nonlocal SIGPIPE_count
            nonlocal tids

            SIGPIPE_count += 1
            tids.append(t.thread_id)

        d = debugger(RESOLVE_EXE("signals_multithread_det_test"))

        # Set a breakpoint to stop the program before the end of the receiver thread
        r = d.run()

        bp = d.breakpoint(TEST_SIGNAL_MULTITHREAD_SEND_SIGNAL_BP_ADDRESS, hardware=True, file="binary")

        catcher1 = d.catch_signal("SIGUSR1", callback=catcher_SIGUSR1)
        catcher2 = d.catch_signal("SIGTERM", callback=catcher_SIGTERM)
        catcher3 = d.catch_signal("SIGINT", callback=catcher_SIGINT)
        catcher4 = d.catch_signal("SIGQUIT", callback=catcher_SIGQUIT)
        catcher5 = d.catch_signal("SIGPIPE", callback=catcher_SIGPIPE)

        d.cont()

        received = []
        for _ in range(13):
            received.append(r.recvline(timeout=5))

        r.sendline(b"sync")

        d.wait()
        if bp.hit_on(d.threads[1]):
            d.threads[1].signal = "SIGUSR1"
            d.cont()
        received.append(r.recvline(timeout=5))
        received.append(r.recvline(timeout=5))

        receiver = d.threads[1].thread_id
        d.kill()
        d.terminate()

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

        # Count the number of times each signal was received
        self.assertEqual(received.count(b"Received signal on receiver 10"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 15"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 2"), 2)
        self.assertEqual(received.count(b"Received signal on receiver 3"), 3)
        self.assertEqual(received.count(b"Received signal on receiver 13"), 3)

        set_tids = set(tids)
        self.assertEqual(len(set_tids), 1)
        self.assertEqual(set_tids.pop(), receiver)
