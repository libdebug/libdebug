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
    def test_single_thread_continue(self):
        # This function checks that the single-thread cont works correctly. 
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

        # calling finish on our target thread should not affect the state of other threads
        thread.cont()
        d.wait()

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)
        
        assert target_state != new_target_state

        d.kill()
        d.terminate()
    
    def test_single_thread_continue_wait(self):
        # This function checks that both the single-thread cont and wait work correctly. 
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

        # calling finish on our target thread should not affect the state of other threads
        thread.cont()
        thread.wait()
        
        assert not thread.running

        new_other_threads_state = [save_thread_state(x) for x in other_threads]
        assert all(x == y for x, y in zip(other_threads_state, new_other_threads_state))

        new_target_state = save_thread_state(thread)
        
        assert target_state != new_target_state

        d.kill()
        d.terminate()
        
    def test_single_thread_interrupt(self):
        # This function checks that the single-thread interrupt works correctly. 
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
        
        d.interrupt()
        d.kill()
        d.terminate()