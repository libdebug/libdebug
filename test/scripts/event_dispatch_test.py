"""Mutation during event dispatch must have deterministic phase boundaries."""

from collections import defaultdict
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

from libdebug.data.event_hook import EventHook
from libdebug.data.event_type import EventType
from libdebug.ptrace.ptrace_status_handler import PtraceStatusHandler


class EventDispatchTest(TestCase):
    def test_mutations(self):
        for post in (False, True):
            for mutation in ("self", "remove", "disable", "add"):
                with self.subTest(post=post, mutation=mutation):
                    engine = SimpleNamespace(
                        debugging_interface=Mock(), event_hooks=defaultdict(list),
                        _ensure_process_stopped=Mock(), _is_migrated_to_gdb=False,
                    )
                    handler = PtraceStatusHandler(engine)
                    hooks = engine.event_hooks[EventType.EXEC]
                    seen = []
                    def make(name, callback=None):
                        hook = EventHook(
                            event=EventType.EXEC, _post_hook=post, _internal_debugger=engine,
                            callback=callback or (lambda t, h: seen.append(name)),
                        )
                        hooks.append(hook)
                        return hook
                    def mutate(t, h):
                        seen.append("first")
                        if mutation == "self":
                            hooks.remove(h)
                        elif mutation == "remove":
                            hooks.remove(second)
                        elif mutation == "disable":
                            second.disable()
                        elif mutation == "add":
                            make("added")
                    first = make("first", mutate)
                    second = make("second")
                    third = make("third")
                    dispatch = handler._execute_post_hooks if post else handler._execute_pre_hooks
                    dispatch(EventType.EXEC, None)
                    expected = ["first", "third"] if mutation in ("remove", "disable") else ["first", "second", "third"]
                    self.assertEqual(seen, expected)
                    self.assertEqual(third.hit_count, 1)
                    # Disable the mutator so the second dispatch checks only deferred work.
                    first.disable()
                    seen.clear()
                    dispatch(EventType.EXEC, None)
                    expected = ["third"] if mutation in ("remove", "disable") else ["second", "third"]
                    if mutation == "add":
                        expected.append("added")
                    self.assertEqual(seen, expected)

