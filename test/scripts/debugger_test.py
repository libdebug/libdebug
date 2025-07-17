#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase

from libdebug import debugger


class DebuggerTest(TestCase):
    def test_get_set_argv_and_path(self):
        d = debugger("/bin/ls")

        # Ensure we can access argv
        self.assertEqual(d.argv, ["/bin/ls"])
        self.assertEqual(d.path, "/bin/ls")

        d.argv = ["/bin/ls", "-l"]

        # Ensure that we can set argv
        self.assertEqual(d.argv, ["/bin/ls", "-l"])
        self.assertEqual(d.path, "/bin/ls")

        d.argv = "/bin/true"

        # Ensure that we can set argv to a string and have it converted to a list
        self.assertEqual(d.argv, ["/bin/true"])
        self.assertEqual(d.path, "/bin/true")

        with self.assertRaises(TypeError):
            # Ensure that we can't set argv to an invalid type
            d.argv = 12345

        d.run()

        # Ensure that changing argv actually changes the process being debugged
        self.assertEqual(d.argv, ["/bin/true"])
        self.assertIn("true", d.maps[0].backing_file)
        self.assertIn("true", d._internal_debugger._process_full_path)
        self.assertIn("true", d._internal_debugger._process_name)

        with self.assertRaises(RuntimeError):
            # Can't do it know because the process is being debugger
            d.argv = "/bin/ls"

        # Warm the caches
        d._internal_debugger._process_full_path
        d._internal_debugger._process_name

        d.kill()

        d.argv = "/bin/ls"

        # Ensure that changing argv invalidates the caches
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_full_path
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_name

        d.run()
        d.kill()

        # Ensure that we can change path
        d.path = "/bin/true"

        d.run()

        # argv = ["/bin/ls"] but path = "/bin/true"
        self.assertEqual(d.argv, ["/bin/ls"])
        self.assertEqual(d.path, "/bin/true")
        self.assertIn("true", d.maps[0].backing_file)
        self.assertIn("true", d._internal_debugger._process_full_path)
        self.assertIn("true", d._internal_debugger._process_name)

        d.kill()

        d.argv = "/bin/false"

        d.run()

        # argv = ["/bin/false"] but path = "/bin/true"
        self.assertEqual(d.argv, ["/bin/false"])
        self.assertEqual(d.path, "/bin/true")
        self.assertIn("true", d.maps[0].backing_file)
        self.assertIn("true", d._internal_debugger._process_full_path)
        self.assertIn("true", d._internal_debugger._process_name)

        with self.assertRaises(RuntimeError):
            # Can't do it know because the process is being debugged
            d.path = "/bin/ls"

        d.kill()

        d.path = "/bin/ls"

        # Ensure that changing path invalidates the caches
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_full_path
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_name

        d.terminate()

    def test_get_set_env(self):
        d = debugger("/bin/ls")

        # If we don't set env, it should be None
        self.assertIsNone(d.env)

        # Ensure that we can set env
        d.env = {"TEST_ENV": "test_value"}

        self.assertEqual(d.env, {"TEST_ENV": "test_value"})

        d.run()

        # Ensure that we cannot change env while the process is running
        with self.assertRaises(RuntimeError):
            d.env = {"TEST_ENV": "new_value"}

        d.kill()

        # Ensure that we can clear the env
        d.env = None

        self.assertIsNone(d.env)

        d.terminate()