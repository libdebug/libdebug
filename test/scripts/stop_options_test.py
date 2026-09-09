"""Stop options remain configurable between traced processes."""

from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.data.event_type import EventType


class StopOptionsTest(TestCase):
    def test_inactive_options(self):
        for option in ("exec", "fork", "clone"):
            with self.subTest(option=option):
                binary = RESOLVE_EXE("exec_lifecycle")
                event = EventType[option.upper()]
                d = debugger(binary)
                engine = d._internal_debugger
                attribute = "stop_on_" + option
                owned = "_" + attribute + "_hook"
                try:
                    setattr(d, attribute, True)
                    d.run()
                    self.assertEqual(len(engine.event_hooks[event]), 1)
                    d.kill()
                    try:
                        setattr(d, attribute, False)
                    except RuntimeError as error:
                        self.fail(f"disabling {attribute} after kill must work: {error}")
                    self.assertFalse(getattr(d, attribute))
                    self.assertIsNone(getattr(engine, owned))
                    self.assertEqual(len(engine.event_hooks[event]), 0)
                    d.run()
                    self.assertEqual(len(engine.event_hooks[event]), 0)
                    for enabled in (True, True, False, False, True):
                        setattr(d, attribute, enabled)
                        self.assertEqual(len(engine.event_hooks[event]), int(enabled))
                    d.kill()
                    d.run()
                    self.assertEqual(len(engine.event_hooks[event]), 1)
                    d.cont()
                    d.wait()
                    self.assertEqual(d.exit_code, 0)
                finally:
                    if engine.is_debugging:
                        d.kill()
                    d.terminate()
