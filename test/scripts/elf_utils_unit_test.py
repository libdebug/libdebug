#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
from unittest import TestCase

from libdebug.utils.elf_utils import resolve_argv_path


class ELFUtilsUnitTest(TestCase):
    def test_resolve_argv_path(self):
        # Let's ensure that "/usr/bin/ls" and "/usr/bin/cat" exist for this test to be valid
        self.assertTrue(os.path.exists("/usr/bin/ls"))
        self.assertTrue(os.path.exists("/usr/bin/cat"))

        # Absolute paths should be returned as-is
        self.assertEqual(resolve_argv_path("/usr/bin/ls"), "/usr/bin/ls")
        self.assertEqual(resolve_argv_path("/usr/bin/does_not_exist"), "/usr/bin/does_not_exist")

        # Commands in PATH should be resolved correctly
        self.assertEqual(resolve_argv_path("ls"), "/usr/bin/ls")
        self.assertEqual(resolve_argv_path("cat"), "/usr/bin/cat")

        # Commands not in PATH should be returned as-is
        self.assertEqual(resolve_argv_path("does_not_exist"), "does_not_exist")

        # Local paths should be resolved relative to the current working directory
        # Let's assume the cwd is /home/user/libdebug/test for this test
        # We are checking that ./ls is resolved to /home/user/libdebug/test/ls
        self.assertEqual(resolve_argv_path("./ls"), os.path.abspath("./ls"))
        self.assertNotEqual(resolve_argv_path("./ls"), "/usr/bin/ls")
        # ../cat is resolved to /home/user/libdebug/cat instead
        self.assertEqual(resolve_argv_path("../cat"), os.path.abspath("../cat"))
        self.assertNotEqual(resolve_argv_path("../cat"), "/usr/bin/cat")

        # Relative-to-home paths should be resolved correctly
        home = os.path.expanduser("~")
        self.assertEqual(resolve_argv_path("~/ls"), os.path.join(home, "ls"))
        self.assertEqual(resolve_argv_path("~/cat"), os.path.join(home, "cat"))

        # Relative paths should be resolved relative to the current working directory
        # Let's assume the cwd is /home/user/libdebug/test for this test
        # We are checking that "test/provola" is resolved to /home/user/libdebug/test/test/provola
        self.assertEqual(resolve_argv_path("test/provola"), os.path.abspath("test/provola"))