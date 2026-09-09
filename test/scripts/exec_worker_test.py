"""Worker exec must make progress while the leader is at an exit stop."""

from unittest import TestCase, skipUnless

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.data.event_type import EventType
from libdebug.utils.libcontext import libcontext


class ExecWorkerTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_worker_exec(self):
        for peers, stop in ((0, True), (3, True), (3, False)):
            with self.subTest(peers=peers, stop=stop):
                worker = RESOLVE_EXE("exec_worker")
                new = RESOLVE_EXE("exec_new")
                d = debugger([worker, new, str(peers)], stop_on_exec=stop)
                try:
                    for _ in range(3):
                        pipe = d.run()
                        d.breakpoint("unused")
                        d.breakpoint("unused+1", hardware=True)
                        exits = []
                        d.hook_event(EventType.EXIT, callback=lambda t, h: exits.append(t.tid), post_hook=True)
                        d.cont()
                        self.assertEqual(pipe.recvline(), b"WORKER EXEC")
                        d.wait()
                        if stop:
                            live = [t for t in d.threads if not t.dead]
                            self.assertEqual(len(live), 1)
                            self.assertEqual(live[0].tid, d.pid)
                            self.assertFalse(live[0].zombie)
                            self.assertGreater(live[0].instruction_pointer, 0)
                            self.assertIn(d.pid, exits, "leader exit notification must survive the barrier")
                            bp = d.breakpoint("probe", file=new)
                            d.cont()
                            d.wait()
                            self.assertEqual(bp.hit_count, 1)
                            d.cont()
                            d.wait()
                        self.assertEqual(pipe.recvline(), b"IMAGE 42")
                        self.assertEqual(d.exit_code, 0)
                        d.kill()
                finally:
                    if d._internal_debugger.is_debugging:
                        d.kill()
                    d.terminate()
