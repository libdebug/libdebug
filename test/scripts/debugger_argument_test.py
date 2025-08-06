#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase

from libdebug import debugger


class DebuggerArgumentTest(TestCase):
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
            # Can't do it now because the process is being debugged
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
            # Can't do it now because the process is being debugged
            d.path = "/bin/ls"

        d.kill()

        d.path = "/bin/ls"

        # Ensure that changing path invalidates the caches
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_full_path
        with self.assertRaises(FileNotFoundError):
            d._internal_debugger._process_name

        d.terminate()

        # If path is set, we can set argv to an empty list
        d = debugger("/bin/ls", path="/bin/true")

        d.argv = []

        self.assertEqual(d.argv, [])
        self.assertIn("true", d.path)

        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()
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

    def test_argument_list(self):
        # We cannot change argv while the process is being debugged
        d = debugger("/bin/ls")
        d.run()

        with self.assertRaises(RuntimeError) as cm:
            d.argv[0] = "/bin/true"
        self.assertEqual(str(cm.exception), "Cannot change argv while the process is running. Please kill it first.")

        d.kill()
        d.terminate()

        # We can change argv when the process is not being debugged
        d = debugger("/bin/ls")
        d.argv[0] = "/bin/true"

        self.assertEqual(d.argv, ["/bin/true"])
        self.assertEqual(d.path, "/bin/true")

        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()

        d.argv[0] = "/bin/false"
        self.assertEqual(d.argv, ["/bin/false"])
        self.assertEqual(d.path, "/bin/false")

        d.run()
        self.assertIn("false", d.maps[0].backing_file)
        d.kill()
        d.terminate()

        # We cannot pop the last argument from argv
        d = debugger("/bin/ls")

        with self.assertRaises(ValueError) as cm:
            d.argv.pop()
        self.assertIn("Argument list must maintain at least one element", str(cm.exception))

        d.terminate()

        # We can insert arguments into argv at any position and get path revalidated
        d = debugger("/bin/true")

        d.argv.insert(0, "ls")
        self.assertEqual(d.argv, ["ls", "/bin/true"])
        self.assertIn("ls", d.path) # either /usr/bin/ls or /bin/ls

        d.terminate()

        # Changing argv[0] to a non-existing file should raise FileNotFoundError
        d = debugger("/bin/ls")

        with self.assertRaises(FileNotFoundError) as cm:
            d.argv[0] = "/bin/non_existing_file"
        self.assertIn("/bin/non_existing_file", str(cm.exception))
        self.assertEqual(d.argv, ["/bin/ls"])
        self.assertEqual(d.path, "/bin/ls")

        d.terminate()

        # We cannot change argv when debugging even if path is set
        d = debugger("/bin/ls", path="/bin/true")

        d.run()

        with self.assertRaises(RuntimeError) as cm:
            d.argv[0] = "/bin/false"
        self.assertEqual(str(cm.exception), "Cannot change argv while the process is running. Please kill it first.")

        d.kill()
        d.terminate()

        # We can change argv when not debugging and it won't change path
        d = debugger("/bin/ls", path="/bin/true")
        d.argv[0] = "/bin/false"
        self.assertEqual(d.argv, ["/bin/false"])
        self.assertEqual(d.path, "/bin/true")

        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()

        d.terminate()

        # When path is set, we can pop the last argument from argv
        d = debugger("/bin/ls", path="/bin/true")

        d.argv.pop()
        self.assertEqual(d.argv, [])
        self.assertEqual(d.path, "/bin/true")
        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()

        d.terminate()

        # When path is set, changing argv[0] to a non-existing file should NOT raise FileNotFoundError
        d = debugger("/bin/ls", path="/bin/true")
        d.argv[0] = "/bin/non_existing_file"
        self.assertEqual(d.argv, ["/bin/non_existing_file"])
        self.assertEqual(d.path, "/bin/true")

        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()

        d.terminate()

        # We have to ensure that changing argv[0] invalidates the cache
        d = debugger("/bin/ls")

        d.run()
        _ = d._internal_debugger._process_full_path  # Warm the cache
        _ = d._internal_debugger._process_name     # Warm the cache
        d.kill()

        d.argv[0] = "/bin/true"

        with self.assertRaises(FileNotFoundError):
            _ = d._internal_debugger._process_full_path
        with self.assertRaises(FileNotFoundError):
            _ = d._internal_debugger._process_name

        d.run()
        self.assertIn("true", d.maps[0].backing_file)
        d.kill()

        d.terminate()

        # Changing argv[0] shouldn't invalidate the cache if the path is set
        d = debugger("/bin/ls", path="/bin/true")

        d.run()
        _ = d._internal_debugger._process_full_path  # Warm the cache
        _ = d._internal_debugger._process_name     # Warm the cache
        d.kill()

        d.argv[0] = "/bin/false"

        # The caches should still be valid
        self.assertIn("true", d._internal_debugger._process_full_path)
        self.assertIn("true", d._internal_debugger._process_name)

        d.terminate()

    def test_argv_copy(self):
        # We check that instancing the debugger with a list copies it
        argv = ["/bin/ls", "-l"]
        d = debugger(argv)
        self.assertEqual(d.argv, argv)
        argv.append("-a")
        self.assertNotEqual(d.argv, argv)
        self.assertEqual(d.argv, ["/bin/ls", "-l"])
        d.terminate()

        # We check that setting argv to a list copies it
        argv = ["/bin/ls", "-l"]
        d = debugger("/bin/true")
        d.argv = argv
        self.assertEqual(d.argv, argv)
        argv.append("-a")
        self.assertNotEqual(d.argv, argv)
        self.assertEqual(d.argv, ["/bin/ls", "-l"])
        d.terminate()