"""Waits belong to the tracer thread, independently of tracee process groups."""

import subprocess
import sys
from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class ExecWaitTest(TestCase):
    def test_changed_groups(self):
        for mode in ("group", "session"):
            with self.subTest(mode=mode):
                binary = RESOLVE_EXE("exec_pgroups")
                debuggers = [debugger([binary, mode]) for _ in range(2)]
                unrelated = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(.2); raise SystemExit(37)"]
                )
                try:
                    pipes = [d.run() for d in debuggers]
                    bps = [d.breakpoint("checkpoint") for d in debuggers]
                    for d in debuggers:
                        d.cont()
                    for pipe in pipes:
                        self.assertEqual(pipe.recvline(), b"CHANGED")
                    for d, bp in zip(debuggers, bps):
                        d.wait()
                        self.assertEqual(bp.hit_count, 1)
                        d.cont()
                    for d in debuggers:
                        d.wait()
                        self.assertEqual(d.exit_code, 0)
                    self.assertEqual(unrelated.wait(), 37, "tracer stole an unrelated subprocess event")
                finally:
                    for d in debuggers:
                        d.kill()
                        d.terminate()
                    if unrelated.poll() is None:
                        unrelated.kill()
                    unrelated.wait()
