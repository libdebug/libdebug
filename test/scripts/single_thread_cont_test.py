#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


def save_thread_state(thread):
    state = b""
    for attr in dir(thread.regs.register_file):
        state += getattr(thread.regs.register_file, attr).to_bytes(8, "little")
    return state


class SingleThreadContTest(unittest.TestCase):
    def test_single_thread_finish_in_other_thread_1(self):
        # this function checks that the single-thread cont works correctly
        # when used for a finish. The other two threads are supposed to be
        # either dead or in a wait.

        d = debugger("binaries/single_thread_cont_test")

        d.run()

        def callback(_, __):
            pass

        do_nothing = d.bp("do_nothing", callback=callback)
        do_nothing_target = d.bp("do_nothing_target")

        d.cont()

        thread = None

        for t in d.threads:
            if do_nothing_target.hit_on(t):
                # t is our target
                thread = t
                break

        assert thread is not None

        other_threads = d.threads.copy()
        other_threads.remove(thread)

        other_threads_state = [save_thread_state(x) for x in other_threads]

        # sanity check
        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        target_state = save_thread_state(thread)

        # calling finish on our target thread should not affect the state of other threads
        thread.finish(heuristic="backtrace")

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)

        assert target_state != new_target_state

        d.kill()
        d.terminate()

    def test_single_thread_finish_in_other_thread_2(self):
        # this function checks that the single-thread cont works correctly
        # when used for a finish. One of the other threads should be stopped
        # at a software breakpoint when finish is called.

        d = debugger("binaries/single_thread_cont_test")

        d.run()

        do_nothing_target = d.bp("do_nothing_target")
        do_nothing_other = d.bp("do_nothing_other")

        d.cont()
        d.wait()

        target, other = None, None

        for t in d.threads:
            if do_nothing_target.hit_on(t):
                assert target is None
                target = t
                break

            if do_nothing_other.hit_on(t):
                assert other is None
                other = t
                break

        while len(d.threads) < 3:
            d.threads[0].step()

        if not target:
            target = d.threads[2] if d.threads[1] == other else d.threads[1]

        if not other:
            other = d.threads[2] if d.threads[1] == target else d.threads[1]

        if not do_nothing_target.hit_on(target):
            target.step_until(do_nothing_target.address)

        if not do_nothing_other.hit_on(other):
            other.step_until(do_nothing_other.address)

        # at this point, both the target thread and the other thread are stuck on a breakpoint
        # save the states

        main_state = save_thread_state(d.threads[0])
        target_state = save_thread_state(target)
        other_state = save_thread_state(other)

        # call finish on the target
        target.finish(heuristic="backtrace")

        assert main_state == save_thread_state(d.threads[0])
        assert other_state == save_thread_state(other)
        assert target_state != save_thread_state(target)

        # sanity check
        other.step()

        assert other_state != save_thread_state(other)

        d.kill()
        d.terminate()

    def test_single_thread_finish_in_other_thread_3(self):
        # this function checks that the single-thread cont works correctly
        # when used for a finish. One of the other threads should be stopped
        # at a hardware breakpoint when finish is called.

        d = debugger("binaries/single_thread_cont_test")

        d.run()

        do_nothing_target = d.bp("do_nothing_target")
        do_nothing_other = d.bp("do_nothing_other", hardware=True)

        d.cont()
        d.wait()

        target, other = None, None

        for t in d.threads:
            if do_nothing_target.hit_on(t):
                assert target is None
                target = t
                break

            if do_nothing_other.hit_on(t):
                assert other is None
                other = t
                break

        while len(d.threads) < 3:
            d.threads[0].step()

        if not target:
            target = d.threads[2] if d.threads[1] == other else d.threads[1]

        if not other:
            other = d.threads[2] if d.threads[1] == target else d.threads[1]

        if not do_nothing_target.hit_on(target):
            target.step_until(do_nothing_target.address)

        if not do_nothing_other.hit_on(other):
            other.step_until(do_nothing_other.address)

        # at this point, both the target thread and the other thread are stuck on a breakpoint
        # save the states

        main_state = save_thread_state(d.threads[0])
        target_state = save_thread_state(target)
        other_state = save_thread_state(other)

        # call finish on the target
        target.finish(heuristic="backtrace")

        assert main_state == save_thread_state(d.threads[0])
        assert other_state == save_thread_state(other)
        assert target_state != save_thread_state(target)

        # sanity check
        other.step()

        assert other_state != save_thread_state(other)

        d.kill()
        d.terminate()
