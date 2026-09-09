"""User-generated traps must retain signal-delivery provenance."""

from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class ExecSignalTest(TestCase):
    def test_user_sigtrap(self):
        for mode in ("kill", "raise", "queue"):
            with self.subTest(mode=mode):
                binary = RESOLVE_EXE("exec_sigtrap")
                d = debugger([binary, mode])
                try:
                    pipe = d.run()
                    caught = []
                    catcher = d.catch_signal("SIGTRAP", callback=lambda t, h: caught.append(t.signal))
                    bp = d.breakpoint("checkpoint")
                    d.cont()
                    d.wait()
                    self.assertEqual(bp.hit_count, 1)
                    self.assertEqual(catcher.hit_count, 0)
                    d.step()
                    self.assertEqual(catcher.hit_count, 0)
                    for _ in range(5):
                        if d.dead:
                            break
                        d.cont()
                        d.wait()
                    self.assertEqual(catcher.hit_count, 1, "user SIGTRAP must reach the catcher")
                    self.assertEqual(caught, ["SIGTRAP"])
                    self.assertEqual(pipe.recvline(), b"HANDLED 1")
                    self.assertEqual(d.exit_code, 0)
                finally:
                    d.kill()
                    d.terminate()
