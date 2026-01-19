#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import shutil
from unittest import TestCase

from libdebug.utils.elf_utils import resolve_argv_path


class ELFUtilsUnitTest(TestCase):
    def test_resolve_argv_path(self):
        ls_path = shutil.which("ls")
        cat_path = shutil.which("cat")
        self.assertIsNotNone(ls_path, "Cannot resolve `ls` in PATH on this system")
        self.assertIsNotNone(cat_path, "Cannot resolve `cat` in PATH on this system")

        # Absolute paths should be returned as-is
        self.assertEqual(resolve_argv_path(ls_path), ls_path)
        invalid_abs = os.path.join(os.path.dirname(ls_path), "does_not_exist")
        self.assertEqual(resolve_argv_path(invalid_abs), invalid_abs)

        # Commands in PATH should be resolved correctly
        self.assertEqual(resolve_argv_path("ls"), ls_path)
        self.assertEqual(resolve_argv_path("cat"), cat_path)

        # Commands not in PATH should be returned as-is
        self.assertEqual(resolve_argv_path("does_not_exist"), "does_not_exist")

        # Local paths should be resolved relative to the current working directory
        # Let's assume the cwd is /home/user/libdebug/test for this test
        # We are checking that ./ls is resolved to /home/user/libdebug/test/ls
        self.assertEqual(resolve_argv_path("./ls"), os.path.abspath("./ls"))
        self.assertNotEqual(resolve_argv_path("./ls"), ls_path)
        # ../cat is resolved to /home/user/libdebug/cat instead
        self.assertEqual(resolve_argv_path("../cat"), os.path.abspath("../cat"))
        self.assertNotEqual(resolve_argv_path("../cat"), cat_path)

        # Relative-to-home paths should be resolved correctly
        home = os.path.expanduser("~")
        self.assertEqual(resolve_argv_path("~/ls"), os.path.join(home, "ls"))
        self.assertEqual(resolve_argv_path("~/cat"), os.path.join(home, "cat"))

        # Relative paths should be resolved relative to the current working directory
        # Let's assume the cwd is /home/user/libdebug/test for this test
        # We are checking that "test/provola" is resolved to /home/user/libdebug/test/test/provola
        self.assertEqual(resolve_argv_path("test/provola"), os.path.abspath("test/provola"))