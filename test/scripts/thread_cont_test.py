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

class ThreadContTest(TestCase):        
    def test_continue_thread_scoped(self):
        # This function checks that the thread-scoped cont works correctly. 
        # The other two threads are supposed to be either dead or in a wait.
        d = debugger(RESOLVE_EXE("single_thread_cont_test"))
        d.run()
        
        do_nothing_target = d.bp("do_nothing_target")

        # This is a process-scoped continue
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

        # Calling cont on our target thread should not affect the state of other threads
        thread.cont()
        d.wait()

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)
        
        assert target_state != new_target_state

        d.kill()
        d.terminate()
    
    # def test_continue_thread_scoped_double(self):
    #     # This function checks that the thread-scoped cont works correctly when called twice on different threads. 
    #     # The other two threads are supposed to be either dead or in a wait.
    #     d = debugger(RESOLVE_EXE("single_thread_cont_test"))
    #     d.run()
        
    #     do_nothing_target = d.bp("do_nothing_target")

    #     # This is a process-scoped continue
    #     d.cont()

    #     thread = None

    #     for t in d.threads:
    #         if do_nothing_target.hit_on(t):
    #             # t is our target
    #             thread = t
    #             break

    #     self.assertIsNotNone(thread)

    #     other_threads = d.threads.copy()
    #     other_threads.remove(thread)
    #     thread2 = other_threads[0]
    #     other_threads.remove(thread2)

    #     other_threads_state = [save_thread_state(x) for x in other_threads]

    #     # sanity check
    #     new_other_threads_state = [save_thread_state(x) for x in other_threads]
    #     self.assertTrue(all(x == y for x, y in zip(other_threads_state, new_other_threads_state)))

    #     target_state = save_thread_state(thread)
    #     target2_state = save_thread_state(thread2)

    #     # Calling cont on our target thread should not affect the state of other threads
    #     thread.cont()
    #     thread2.cont()
        
    #     self.assertTrue(thread.running)
    #     self.assertTrue(thread2.running)
    #     self.assertTrue(thread.scheduled)
    #     self.assertTrue(thread2.scheduled)
        
    #     for t in other_threads:
    #         self.assertFalse(t.running)
    #         self.assertFalse(t.scheduled)
        
    #     d.wait()

    #     new_other_threads_state = [save_thread_state(x) for x in other_threads]
    #     self.assertTrue(all(x == y for x, y in zip(other_threads_state, new_other_threads_state)))

    #     new_target_state = save_thread_state(thread)
    #     new_target_state2 = save_thread_state(thread2)
        
    #     self.assertNotEqual(target_state, new_target_state)
    #     self.assertNotEqual(target2_state, new_target_state2)

    #     d.kill()
    #     d.terminate()
    
    def test_continue_wait_thread_scoped(self):
        # This function checks that both the thread-scoped cont and wait work correctly. 
        # The other two threads are supposed to be running.
        d = debugger(RESOLVE_EXE("single_thread_cont_test"))
        d.run()

        do_nothing_target = d.bp("do_nothing_target")

        # This is a process-scoped continue
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

        # Calling cont on our target thread should not affect the state of other threads
        thread.cont()
        thread.wait()
        
        assert not thread.running

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)
        
        assert target_state != new_target_state

        d.kill()
        d.terminate()
        
    def test_interrupt_thread_scoped(self):
        # This function checks that the thread-scoped interrupt works correctly. 
        # The other two threads are supposed to be still running.
        d = debugger(RESOLVE_EXE("io_thread_cont_test"))
        r = d.run()
        
        bp1 = d.bp("task2")
        bp2 = d.bp("task3")

        # This is a process-scoped continue
        d.cont()

        for _ in range(2):
            # This is a process-scoped wait
            d.wait()
            for t in d.threads:
                if bp1.hit_on(t):
                    # t is our target
                    thread = t
                    break
                elif bp2.hit_on(t):
                    # t is our target
                    thread2 = t
                    break
            # This is another process-scoped continue
            d.cont()
            
        
        # Make sure that all threads are running
        while len(d.threads) < 6:
            pass
    
        other_threads = d.threads.copy()
        other_threads.remove(thread)
        other_threads.remove(thread2)
            
        # This is a thread-scoped interrupt
        thread.interrupt()
        thread2.interrupt()
                
        assert not thread.running
        assert not thread2.running
        
        for t in other_threads:
            assert t.running, f"Thread {t.tid} is not running"
        
        messages = []
        for _ in range(5):
            messages.append(r.recvline())

        # We expect to have received the following messages
        assert b"Thread 1 is running..." in messages
        assert b"Thread 2 is running..." in messages
        assert b"Thread 3 is running..." in messages
        assert b"Thread 4 is running..." in messages
        assert b"Thread 5 is running..." in messages
        
        # Send the input to unlock the threads
        r.sendline(b"Io_no")
        
        messages = []
        for _ in range(3):
            messages.append(r.recvline())
                    
        # The task 2 should have been interrupted
        assert b"Thread 1 finished." in messages
        assert b"Thread 2 finished." not in messages
        assert b"Thread 3 finished." not in messages
        assert b"Thread 4 finished." in messages
        assert b"Thread 5 finished." in messages
        
        # Interrupt the other threads
        d.interrupt()
        
        # Continue all the threads
        d.cont()
        
        d.wait()
        d.kill()
        d.terminate()
        
    
    def test_finish_thread_scoped(self):
        # This function checks that the thread-scoped finish works correctly.
        # The other two threads are supposed to be either dead or in a wait.

        d = debugger(RESOLVE_EXE("single_thread_cont_test"))

        d.run()

        def callback(_, __):
            pass

        d.bp("do_nothing", callback=callback)
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

        # Sanity check
        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        target_state = save_thread_state(thread)

        # Salling finish on our target thread should not affect the state of other threads
        thread.finish(heuristic="backtrace")

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)

        assert target_state != new_target_state

        d.kill()
        d.terminate()
        
    def test_step_thread_scoped(self):
        # This function checks that the thread-scoped step works correctly. 
        # The other two threads are supposed to be either dead or stopped.

        d = debugger(RESOLVE_EXE("single_thread_cont_test"))

        d.run()

        def callback(_, __):
            pass

        d.bp("do_nothing", callback=callback)
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

        # Sanity check
        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        target_state = save_thread_state(thread)

        # Calling step on our target thread should not affect the state of other threads
        thread.step()

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)

        assert target_state != new_target_state

        d.kill()
        d.terminate()

    def test_finish_step_thread_scoped(self):
        # This function checks that the thread-scoped finish and step work correctly.
        # One of the other threads should be stopped at a software breakpoint when finish is called.

        d = debugger(RESOLVE_EXE("single_thread_cont_test"))

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

        # At this point, both the target threads and the other thread are stuck on a breakpoint.
        # Aave the states

        main_state = save_thread_state(d.threads[0])
        target_state = save_thread_state(target)
        other_state = save_thread_state(other)

        # Call finish on the target
        target.finish(heuristic="backtrace")

        assert main_state == save_thread_state(d.threads[0])
        assert other_state == save_thread_state(other)
        assert target_state != save_thread_state(target)

        # Sanity check
        other.step()

        assert other_state != save_thread_state(other)

        d.kill()
        d.terminate()
        
    def test_finish_step_step_until_thread_scoped(self):
        # This function checks that the thread-scoped finish, step, and step_until work correctly.
        # One of the other threads should be stopped at a hardware breakpoint when finish is called.

        d = debugger(RESOLVE_EXE("single_thread_cont_test"))

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