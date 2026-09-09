"""Isolated regression tests for lifecycle status dispatch."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler


class ExecStatusTest(TestCase):
    def test_clone_consumed_stop(self):
        interface = Mock()
        handler = PtraceStatusHandler(SimpleNamespace(debugging_interface=interface))
        for records, should_wait in [
            ([(123, 4991, 0)], False),
            ([], True),
            ([(456, 4991, 0)], True),
            ([(123, 1407, 0)], True),
        ]:
            with self.subTest(records=records), patch("os.waitpid") as waitpid:
                interface.reset_mock()
                handler._handle_clone(123, records)
                self.assertEqual(waitpid.call_count, int(should_wait))
                if should_wait:
                    waitpid.assert_called_once_with(123, 0)
                interface.register_new_thread.assert_called_once_with(123)
