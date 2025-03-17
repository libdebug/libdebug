#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
from unittest import TestCase, skipUnless
from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger

class EventsTest(TestCase):
    def test_events_bp(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        bp = d.breakpoint("random_function")
        

        d.cont()

        self.assertTrue(bp.hit_on(d))
        
        self.assertTrue(d.event_type == "breakpoint")
        self.assertTrue(d.event_type == "BREAKPOINT")
        self.assertTrue(d.event_type == "Breakpoint")
        self.assertTrue(d.event_type == d.threads[0].event_type)

        d.kill()
        d.terminate()
    
    def test_events_bp_threads(self):
        d = debugger(RESOLVE_EXE("thread_test"))

        d.run()

        bp_t0 = d.breakpoint("do_nothing", hardware=True)
        bp_t1 = d.breakpoint("thread_1_function", hardware=True)
        bp_t2 = d.breakpoint("thread_2_function", hardware=True)
        bp_t3 = d.breakpoint("thread_3_function", hardware=True)
        
        t1_done, t2_done, t3_done = False, False, False

        d.cont()
        
        for _ in range(15):
            if bp_t0.hit_on(d):
                self.assertTrue(d.event_type == "breakpoint")
                # The other threads should not have hit any event
                for t in d.threads[1:]:
                    self.assertIsNone(t.event_type)
                self.assertTrue(t1_done)
                self.assertTrue(t2_done)
                self.assertTrue(t3_done)
                break
            elif len(d.threads) > 1 and bp_t1.hit_on(d.threads[1]):
                self.assertTrue(d.threads[1].event_type == "breakpoint")
                # The main thread might have hit a clone event
                self.assertIn(d.event_type, [None, "Clone"])
                # The other threads might have hit a exit event
                if len(d.threads) > 2:
                    self.assertIn(d.threads[2].event_type, [None, "Exit"])
                if len(d.threads) > 3:
                    self.assertIn(d.threads[3].event_type, [None, "Exit"])
                t1_done = True
            elif len(d.threads) > 2 and bp_t2.hit_on(d.threads[2]):
                self.assertTrue(d.threads[2].event_type == "breakpoint")
                # The main thread might have hit a clone event
                self.assertIn(d.event_type, [None, "Clone"])
                # The other threads might have hit a exit event
                self.assertIn(d.threads[1].event_type, [None, "Exit"])
                if len(d.threads) > 3:
                    self.assertIn(d.threads[3].event_type, [None, "Exit"])
                t2_done = True
            elif len(d.threads) > 3 and bp_t3.hit_on(d.threads[3]):
                self.assertTrue(d.threads[3].event_type == "breakpoint")
                # The main thread might have hit a clone event
                self.assertIn(d.event_type, [None, "Clone"])
                # The other threads might have hit a exit event
                self.assertIn(d.threads[1].event_type, [None, "Exit"])
                self.assertIn(d.threads[2].event_type, [None, "Exit"])
                t3_done = True
                    
            d.cont()

        d.kill()
        d.terminate()
        
    def test_events_syscall(self):
        d = debugger(RESOLVE_EXE("handle_syscall_test"))

        r = d.run()

        handler = d.handle_syscall("write")

        r.sendline(b"provola")
        
        d.cont()
        
        self.assertTrue(handler.hit_on(d))
        
        self.assertTrue(d.event_type == "syscall")
        self.assertTrue(d.event_type == "SYSCALL")
        self.assertTrue(d.event_type == "Syscall")
        self.assertTrue(d.event_type == d.threads[0].event_type)

        d.kill()
        d.terminate()
        
    def test_events_signal(self):
        d = debugger(RESOLVE_EXE("catch_signal_test"))

        d.run()
        
        catcher = d.catch_signal("SIGPIPE")
        
        d.cont()
        
        self.assertTrue(catcher.hit_on(d))
                
        self.assertTrue(d.event_type == "signal")
        self.assertTrue(d.event_type == "SIGNAL")
        self.assertTrue(d.event_type == "Signal")
        self.assertTrue(d.event_type == d.threads[0].event_type)

        d.kill()
        d.terminate()