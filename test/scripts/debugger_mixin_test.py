#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import io
import logging
from pathlib import Path
from unittest import TestCase, skipUnless

from libdebug import Debugger, debugger
from libdebug.data.event_type import EventType
from libdebug.utils.libcontext import libcontext
from utils.binary_utils import RESOLVE_EXE

from libdebug.debugger.debugger_meta import DebuggerMeta
from libdebug.debugger.mixins.base import EngineBoundMixin


class _MixinA(EngineBoundMixin):
    def foo(self) -> str:
        """Foo from A."""
        return "A"


class _MixinB(EngineBoundMixin):
    def foo(self) -> str:
        """Foo from B."""
        return "B"


class _Base:
    """Non-engine base to ensure filtering works."""


class DebuggerMixinTest(TestCase):
    def setUp(self) -> None:
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self) -> None:
        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_capture_string.close()

    def test_aliases_created_on_collision(self) -> None:
        class _Combined(_MixinA, _MixinB, _Base, metaclass=DebuggerMeta): pass

        combined = _Combined()
        # Primary resolution follows MRO (MixinA before MixinB)
        self.assertEqual(combined.foo(), "A")

        # Aliases should be injected for each conflicting provider
        self.assertTrue(hasattr(_Combined, "_MixinA__foo"))
        self.assertTrue(hasattr(_Combined, "_MixinB__foo"))
        self.assertEqual(combined._MixinA__foo(), "A")
        self.assertEqual(combined._MixinB__foo(), "B")
        self.assertIn("Debugger mixin method collision", self.log_capture_string.getvalue())

    @skipUnless(libcontext.platform == "amd64", "Requires an amd64 host with i386 compatibility")
    def test_custom_debugger_exec(self) -> None:
        class CustomDebugger(_MixinA, Debugger):
            pass

        old = RESOLVE_EXE("exec_old")
        new = RESOLVE_EXE("exec_new")
        d = debugger([old, new], cls=CustomDebugger, stop_on_exec=True,
                     preserve_event_hooks_on_exec=False)
        try:
            pipe = d.run()
            seen = []
            hook = d.hook_event(EventType.EXEC, callback=lambda t, h: seen.append(d.foo()))
            d.cont()
            d.wait()
            self.assertIsInstance(d, CustomDebugger)
            self.assertEqual(seen, ["A"])
            self.assertEqual(hook.hit_count, 1)
            self.assertEqual(d.resume_context.event_type[d.pid], EventType.EXEC)
            self.assertEqual(d.current_path, str(Path(new).resolve()))
            self.assertEqual(d.current_argv, [new])
            self.assertNotIn(hook, d._internal_debugger.event_hooks[EventType.EXEC])
            d.cont()
            d.wait()
            self.assertEqual(pipe.recvline(), b"IMAGE 42")
            self.assertEqual(d.exit_code, 0)
        finally:
            d.kill()
            d.terminate()

    def test_custom_debugger_child_options(self) -> None:
        class CustomDebugger(_MixinA, Debugger):
            pass

        d = debugger(RESOLVE_EXE("exec_fork"), cls=CustomDebugger, stop_on_fork=True,
                     stop_on_exec=True, stop_on_clone=True, preserve_event_hooks_on_exec=False)
        try:
            d.run()
            d.cont()
            d.wait()
            self.assertEqual(len(d.children), 1)
            child = d.children[0]
            self.assertIsInstance(child, CustomDebugger)
            self.assertEqual(child.foo(), "A")
            self.assertTrue(child.stop_on_fork)
            self.assertTrue(child.stop_on_exec)
            self.assertTrue(child.stop_on_clone)
            self.assertFalse(child.preserve_event_hooks_on_exec)
        finally:
            for child in d.children:
                child.kill()
                child.terminate()
            d.kill()
            d.terminate()
