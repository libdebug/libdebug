"""Exec hook lifetime is independent of old-image instrumentation."""

from unittest import TestCase, skipUnless

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.data.event_type import EventType
from libdebug.utils.libcontext import libcontext


class ExecHooksTest(TestCase):
    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_exec_post_hook(self):
        old = RESOLVE_EXE("exec_old")
        new = RESOLVE_EXE("exec_new")
        d = debugger([old, new], stop_on_exec=True)
        try:
            d.run()
            seen = []
            d.hook_event(EventType.EXEC, callback=lambda t, h: seen.append("pre"), post_hook=False)
            d.hook_event(EventType.EXEC, callback=lambda t, h: seen.append("post"), post_hook=True)
            d.cont()
            d.wait()
            self.assertEqual(seen, ["pre", "post"], "exec must run both hook phases")
        finally:
            d.kill()
            d.terminate()

    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_retention_policy(self):
        for preserve in (True, False):
            for flip in (False, True):
                with self.subTest(preserve=preserve, change_inside_callback=flip):
                    image64 = "binaries/amd64/exec_abi64"
                    image32 = "binaries/i386/exec_abi32"
                    retention = preserve
                    d = debugger(
                        [image64, image32, image64],
                        stop_on_exec=True,
                        stop_on_fork=True,
                        stop_on_clone=True,
                        preserve_event_hooks_on_exec=retention,
                    )
                    try:
                        pipe = d.run()
                        engine = d._internal_debugger
                        original_thread = d.threads[0]
                        seen, installed, hits = [], [], []

                        def added_post(t, h):
                            seen.append("added")

                        def pre(t, h):
                            seen.append("pre")
                            if flip:
                                d.preserve_event_hooks_on_exec = not retention
                            installed.append(d.hook_event(EventType.EXEC, callback=added_post, post_hook=True))
                            # Exec has replaced the image, so instrumentation installed here belongs to it.
                            installed.append(
                                d.breakpoint(
                                    "checkpoint",
                                    file=image32 if d.arch == "i386" else image64,
                                    callback=lambda t, bp: hits.append(t.instruction_pointer),
                                )
                            )

                        def post(t, h):
                            seen.append("post")
                            self.assertIs(t, original_thread)
                            self.assertEqual(d.arch, "i386" if h.hit_count == 1 else "amd64")
                            self.assertEqual(t.memory[t.instruction_pointer, 1, "absolute"], b"\x90")
                            self.assertEqual(t.instruction_pointer, t.regs.eip if d.arch == "i386" else t.regs.rip)
                            installed.append(
                                d.hook_event(EventType.EXEC, callback=lambda t, h: seen.append("late"), post_hook=True)
                            )

                        before = d.hook_event(EventType.EXEC, callback=pre, post_hook=False)
                        after = d.hook_event(EventType.EXEC, callback=post, post_hook=True)
                        disabled = d.hook_event(EventType.EXEC, callback=lambda t, h: self.fail("disabled hook ran"))
                        disabled.disable()
                        old_bp = d.breakpoint("checkpoint", callback=True)
                        d.handle_syscall("write", on_enter=True, on_exit=True)
                        d.catch_signal("SIGUSR1", callback=True)
                        utilities = [engine._stop_on_exec_hook, engine._stop_on_fork_hook, engine._stop_on_clone_hook]
                        d.cont()
                        d.wait()
                        self.assertEqual(seen, ["pre", "post", "added"])
                        self.assertEqual(before.hit_count, 1)
                        self.assertEqual(after.hit_count, 1)
                        self.assertFalse(disabled.enabled)
                        self.assertEqual(disabled.hit_count, 0)
                        self.assertNotIn(old_bp, d.breakpoints.values())
                        self.assertEqual(engine.handled_syscalls, {})
                        self.assertEqual(engine.caught_signals, {})
                        for hook in (before, after, disabled):
                            self.assertEqual(hook in engine.event_hooks[EventType.EXEC], retention)
                        for hook in utilities:
                            self.assertEqual(engine.event_hooks[hook.event].count(hook), 1)
                        self.assertIn(installed[0], engine.event_hooks[EventType.EXEC])
                        self.assertIn(installed[-1], engine.event_hooks[EventType.EXEC])
                        d.cont()
                        d.wait()
                        self.assertEqual(len(hits), 1)
                        self.assertEqual(before.hit_count, 2 if retention else 1)
                        self.assertEqual(after.hit_count, 2 if retention else 1)
                        second_retention = not retention if flip else retention
                        if not second_retention:
                            self.assertNotIn(installed[0], engine.event_hooks[EventType.EXEC])
                        for hook in utilities:
                            self.assertEqual(engine.event_hooks[hook.event].count(hook), 1)
                        d.cont()
                        d.wait()
                        self.assertEqual(d.exit_code, 0)
                        for _ in range(3):
                            self.assertEqual(pipe.recvline(), b"ABI")
                    finally:
                        d.kill()
                        d.terminate()

    def test_child_inheritance(self):
        for preserve in (True, False):
            with self.subTest(preserve=preserve):
                binary = RESOLVE_EXE("exec_fork")
                retention = preserve
                d = debugger(binary, stop_on_fork=True, preserve_event_hooks_on_exec=retention)
                try:
                    d.run()
                    d.cont()
                    d.wait()
                    self.assertEqual(len(d.children), 1)
                    self.assertEqual(d.children[0].preserve_event_hooks_on_exec, retention)
                    for child in d.children:
                        child.kill()
                        child.terminate()
                finally:
                    d.kill()
                    d.terminate()

    def test_option_validation(self):
        d = debugger()
        try:
            self.assertTrue(d.preserve_event_hooks_on_exec)
            for bad in (None, 0, 1, "yes", []):
                with self.subTest(value=bad), self.assertRaises(TypeError):
                    d.preserve_event_hooks_on_exec = bad
        finally:
            d.terminate()
