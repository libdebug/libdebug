#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import PLATFORM, BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.data.event_type import EventType

match PLATFORM:
    case "amd64":
        # Address of the main after the fork
        AFTER_FORK_BASIC = 0x12a3
        AFTER_FORK_STRESS = 0x12af
    case "aarch64":
        # Address of the main after the fork
        AFTER_FORK_BASIC = 0xb08
        AFTER_FORK_STRESS = 0xb10
    case "i386":
        # Address of the main after the fork
        AFTER_FORK_BASIC = 0x127f
        AFTER_FORK_STRESS = 0X128b
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")


class MultiprocessingTest(TestCase):
    def test_multiprocessing_hw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_input"))
        
        r = d.run()

        # Breakpoint after the fork
        bp = d.bp(AFTER_FORK_BASIC, file="binary", hardware=True)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()
        
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 1)

        # Let take the child debugger and continue
        dd = d.children[0]
        dd.cont()
        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dd.wait()
        d.wait()

        d.kill()
        dd.kill()

        dd.terminate()
        d.terminate()
        
    def test_multiprocessing_sw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_input"))
        
        r = d.run()

        # Breakpoint after the fork
        bp = d.bp(AFTER_FORK_BASIC, file="binary", hardware=False)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()
        
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 1)

        # Let take the child debugger and continue
        dd = d.children[0]
        dd.cont()
        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dd.wait()
        d.wait()

        d.kill()
        dd.kill()

        dd.terminate()
        d.terminate()
        
    def test_multiprocessing_stress_hw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_stress_input"))
        
        r = d.run()

        # Breakpoint after the fork in the parent
        bp_parent = d.bp(AFTER_FORK_STRESS, file="binary", hardware=True)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()
        
        self.assertTrue(bp_parent.hit_on(d))
        self.assertEqual(len(d.children), 1)
        
        d.cont()

        # Let take the child debugger
        dd = d.children[0]
        
        # Breakpoint after the fork in the first child
        bp_child1 = dd.bp(AFTER_FORK_STRESS, file="binary", hardware=True)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        dd.step()

        dd.cont()

        self.assertIn(dd.process_id, dd.resume_context.event_type)
        self.assertEqual(dd.resume_context.event_type.get(dd.process_id), EventType.FORK)

        dd.cont()
        
        self.assertTrue(bp_child1.hit_on(dd))
        self.assertFalse(bp_child1.hit_on(d))
        self.assertEqual(len(d.children), 1)
        self.assertEqual(len(dd.children), 1)
        
        dd.cont()
        
        # Let take the grandchild debugger
        ddd = dd.children[0]
        
        # Breakpoint after the fork in the second child
        bp_child2 = ddd.bp(AFTER_FORK_STRESS, file="binary", hardware=True)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        ddd.step()

        ddd.cont()

        self.assertIn(ddd.process_id, ddd.resume_context.event_type)
        self.assertEqual(ddd.resume_context.event_type.get(ddd.process_id), EventType.FORK)

        ddd.cont()

        self.assertTrue(bp_child2.hit_on(ddd))
        self.assertFalse(bp_child2.hit_on(dd))
        self.assertFalse(bp_child2.hit_on(d))
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        ddd.cont()
        
        # Let take the grandgrandchild debugger
        dddd = ddd.children[0]
        
        # Breakpoint after the fork in the third child
        bp_child3 = dddd.bp(AFTER_FORK_STRESS, file="binary", hardware=True)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        dddd.step()
        
        dddd.cont()

        self.assertIn(dddd.process_id, dddd.resume_context.event_type)
        self.assertEqual(dddd.resume_context.event_type.get(dddd.process_id), EventType.FORK)

        dddd.cont()
        
        self.assertTrue(bp_child3.hit_on(dddd))
        self.assertFalse(bp_child3.hit_on(ddd))
        self.assertFalse(bp_child3.hit_on(dd))
        self.assertFalse(bp_child3.hit_on(d))
        self.assertEqual(len(dddd.children), 1)
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        dddd.cont()
        
        # Let take the grandgrandgrandchild debugger
        ddddd = dddd.children[0]
        
        # Breakpoint after the fork in the fourth child
        bp_child4 = ddddd.bp(AFTER_FORK_STRESS, file="binary", hardware=True)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        ddddd.step()

        ddddd.cont()
        self.assertIn(ddddd.process_id, ddddd.resume_context.event_type)
        self.assertEqual(ddddd.resume_context.event_type.get(ddddd.process_id), EventType.FORK)
        
        ddddd.cont()
        
        self.assertTrue(bp_child4.hit_on(ddddd))
        self.assertFalse(bp_child4.hit_on(ddd))
        self.assertFalse(bp_child4.hit_on(ddd))
        self.assertFalse(bp_child4.hit_on(dd))
        self.assertFalse(bp_child4.hit_on(d))
        self.assertEqual(len(ddddd.children), 1)
        self.assertEqual(len(dddd.children), 1)
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        ddddd.cont()
        
        # Let take the grandgrandgrandgrandchild debugger
        dddddd = ddddd.children[0]
        
        dddddd.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dddddd.wait()
        ddddd.wait()
        dddd.wait()
        ddd.wait()
        dd.wait()
        d.wait()

        d.kill()
        dd.kill()
        ddd.kill()
        dddd.kill()
        ddddd.kill()
        dddddd.kill()

        dddddd.terminate()
        ddddd.terminate()
        dddd.terminate()
        ddd.terminate()
        dd.terminate()
        d.terminate()

    def test_multiprocessing_stress_sw_bp(self):
        d = debugger(RESOLVE_EXE("multiprocessing_stress_input"))
        
        r = d.run()

        # Breakpoint after the fork in the parent
        bp_parent = d.bp(AFTER_FORK_STRESS, file="binary", hardware=False)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()

        self.assertTrue(bp_parent.hit_on(d))
        self.assertEqual(len(d.children), 1)
        
        d.cont()

        # Let take the child debugger
        dd = d.children[0]
        
        # Breakpoint after the fork in the first child
        bp_child1 = dd.bp(AFTER_FORK_STRESS, file="binary", hardware=False)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        dd.step()

        dd.cont()

        self.assertIn(dd.process_id, dd.resume_context.event_type)
        self.assertEqual(dd.resume_context.event_type.get(dd.process_id), EventType.FORK)

        dd.cont()

        self.assertTrue(bp_child1.hit_on(dd))
        self.assertFalse(bp_child1.hit_on(d))
        self.assertEqual(len(d.children), 1)
        self.assertEqual(len(dd.children), 1)
        
        dd.cont()
        
        # Let take the grandchild debugger
        ddd = dd.children[0]
        
        # Breakpoint after the fork in the second child
        bp_child2 = ddd.bp(AFTER_FORK_STRESS, file="binary", hardware=False)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        ddd.step()
        
        ddd.cont()

        self.assertIn(ddd.process_id, ddd.resume_context.event_type)
        self.assertEqual(ddd.resume_context.event_type.get(ddd.process_id), EventType.FORK)

        ddd.cont()

        self.assertTrue(bp_child2.hit_on(ddd))
        self.assertFalse(bp_child2.hit_on(dd))
        self.assertFalse(bp_child2.hit_on(d))
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        ddd.cont()
        
        # Let take the grandgrandchild debugger
        dddd = ddd.children[0]
        
        # Breakpoint after the fork in the third child
        bp_child3 = dddd.bp(AFTER_FORK_STRESS, file="binary", hardware=False)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        dddd.step()
        
        dddd.cont()

        self.assertIn(dddd.process_id, dddd.resume_context.event_type)
        self.assertEqual(dddd.resume_context.event_type.get(dddd.process_id), EventType.FORK)

        dddd.cont()

        self.assertTrue(bp_child3.hit_on(dddd))
        self.assertFalse(bp_child3.hit_on(ddd))
        self.assertFalse(bp_child3.hit_on(dd))
        self.assertFalse(bp_child3.hit_on(d))
        self.assertEqual(len(dddd.children), 1)
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        dddd.cont()
        
        # Let take the grandgrandgrandchild debugger
        ddddd = dddd.children[0]
        
        # Breakpoint after the fork in the fourth child
        bp_child4 = ddddd.bp(AFTER_FORK_STRESS, file="binary", hardware=False)
        
        # The process is already at the breakpoint address (after fork), we need to skip it
        # and wait for the next hit
        ddddd.step()
        
        ddddd.cont()

        self.assertIn(ddddd.process_id, ddddd.resume_context.event_type)
        self.assertEqual(ddddd.resume_context.event_type.get(ddddd.process_id), EventType.FORK)

        ddddd.cont()

        self.assertTrue(bp_child4.hit_on(ddddd))
        self.assertFalse(bp_child4.hit_on(ddd))
        self.assertFalse(bp_child4.hit_on(ddd))
        self.assertFalse(bp_child4.hit_on(dd))
        self.assertFalse(bp_child4.hit_on(d))
        self.assertEqual(len(ddddd.children), 1)
        self.assertEqual(len(dddd.children), 1)
        self.assertEqual(len(ddd.children), 1)
        self.assertEqual(len(dd.children), 1)
        self.assertEqual(len(d.children), 1)
        
        ddddd.cont()
        
        # Let take the grandgrandgrandgrandchild debugger
        dddddd = ddddd.children[0]
        
        dddddd.cont()
        
        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        dddddd.wait()
        ddddd.wait()
        dddd.wait()
        ddd.wait()
        dd.wait()
        d.wait()

        d.kill()
        dd.kill()
        ddd.kill()
        dddd.kill()
        ddddd.kill()
        dddddd.kill()

        dddddd.terminate()
        ddddd.terminate()
        dddd.terminate()
        ddd.terminate()
        dd.terminate()
        d.terminate()
        
    def test_multiprocessing_no_follow(self):
        d = debugger(RESOLVE_EXE("multiprocessing_input"), follow_children=False)
        
        r = d.run()

        # Breakpoint after the fork
        bp = d.bp(AFTER_FORK_BASIC, file="binary", hardware=True)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()

        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 0)

        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")

        d.wait()
        d.kill()

        d.terminate()
        
    def test_multiprocessing_stress_no_follow(self):
        d = debugger(RESOLVE_EXE("multiprocessing_stress_input"), follow_children=False)
        
        r = d.run()

        # Breakpoint after the fork in the parent
        bp_parent = d.bp(AFTER_FORK_STRESS, file="binary", hardware=True)

        d.cont()

        self.assertIn(d.process_id, d.resume_context.event_type)
        self.assertEqual(d.resume_context.event_type.get(d.process_id), EventType.FORK)

        d.cont()

        self.assertTrue(bp_parent.hit_on(d))
        self.assertEqual(len(d.children), 0)
        
        d.cont()

        r.sendline(b"Io_no")
        self.assertEqual(r.recvline(), b"Enter your input: You entered: Io_no")
        
        d.wait()
        d.kill()

        d.terminate()