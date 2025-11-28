#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import io
import logging
from unittest import TestCase

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
