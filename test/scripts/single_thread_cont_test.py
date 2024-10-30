#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


def save_thread_state(thread):
    state = b""
    for attr in dir(thread.regs.register_file):
        if not attr.startswith("__"):
            state += getattr(thread.regs.register_file, attr).to_bytes(8, "little")
    return state

class SingleThreadContTest(TestCase):
    def setUp(self):
        self.d = debugger(RESOLVE_EXE("single_thread_cont_test"))
        
    def test_single_thread_continue(self):
        # this function checks that the single-thread cont works correctly. 
        # The other two threads are supposed to be either dead or in a wait.

        self.d.run()

        def callback(_, __):
            pass

        self.d.bp("do_nothing", callback=callback)
        do_nothing_target = self.d.bp("do_nothing_target")

        # This is a process-scoped continue
        self.d.cont()

        thread = None

        for t in self.d.threads:
            if do_nothing_target.hit_on(t):
                # t is our target
                thread = t
                break

        assert thread is not None

        other_threads = self.d.threads.copy()
        other_threads.remove(thread)

        other_threads_state = [save_thread_state(x) for x in other_threads]

        # sanity check
        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        target_state = save_thread_state(thread)

        # calling finish on our target thread should not affect the state of other threads
        thread.cont()
        self.d.wait()

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)
        
        assert target_state != new_target_state

        self.d.kill()
        self.d.terminate()