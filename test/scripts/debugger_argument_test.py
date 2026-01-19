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

    def test_envdict(self):
        # We check that we can modify the environment when the process is not running
        d = debugger("/bin/ls", env={"A": "B"})

        self.assertEqual(d.env, {"A": "B"})
        d.env["C"] = "D"
        self.assertEqual(d.env, {"A": "B", "C": "D"})

        d.run()

        self.assertEqual(d.env, {"A": "B", "C": "D"})
        with self.assertRaises(RuntimeError):
            # Cannot modify env while the process is running
            d.env["E"] = "F"

        # The error should have been raised before changing the environment
        self.assertEqual(d.env, {"A": "B", "C": "D"})

        d.kill()

        # We can now modify the environment again
        d.env["E"] = "F"

        d.run()

        # Let's ensure the environment is set correctly
        self.assertEqual(d.env, {"A": "B", "C": "D", "E": "F"})
        with open(f"/proc/{d.pid}/environ", "r") as f:
            env_content = f.read().replace("\x00", "\n").strip()
        self.assertIn("A=B", env_content)
        self.assertIn("C=D", env_content)
        self.assertIn("E=F", env_content)

        # Clearing the environment should not be possible while the process is running
        with self.assertRaises(RuntimeError):
            d.env.clear()

        # The error should have been raised before clearing the environment
        self.assertEqual(d.env, {"A": "B", "C": "D", "E": "F"})

        d.kill()

        # We can clear the environment now
        d.env.clear()

        # Clearing the environment should result in an empty EnvDict
        self.assertEqual(d.env, {})

        # The process should not have any environment variables set
        d.run()

        with open(f"/proc/{d.pid}/environ", "r") as f:
            env_content = f.read().replace("\x00", "\n").strip()
        self.assertEqual(env_content, "")

        # Setting the environment to None should not be possible while the process is running
        with self.assertRaises(RuntimeError):
            d.env = None

        # The error should have been raised before setting the environment to None
        self.assertEqual(d.env, {})

        d.kill()

        # We can set the environment to None now
        d.env = None

        # The environment should be None
        self.assertIsNone(d.env)

        # The process should inherit the environment from the parent
        d.run()

        with open(f"/proc/{d.pid}/environ", "r") as f:
            env_content = f.read().replace("\x00", "\n").strip()
        self.assertNotIn("A=B", env_content)
        self.assertNotEqual(env_content, "")

        # Settings the environment to a new dictionary should not be possible while the process is running
        with self.assertRaises(RuntimeError):
            d.env = {"X": "Y"}

        # The error should have been raised before setting the environment to a new dictionary
        self.assertIsNone(d.env)

        d.kill()

        # We can set the environment to a new dictionary now
        d.env = {"X": "Y"}

        # The environment should be set correctly
        self.assertEqual(d.env, {"X": "Y"})

        d.run()

        with open(f"/proc/{d.pid}/environ", "r") as f:
            env_content = f.read().replace("\x00", "\n").strip()
        self.assertIn("X=Y", env_content)

        d.kill()

        d.terminate()

    def test_envdict_invalid_types(self):
        # Ensure that we cannot set env to an invalid type
        with self.assertRaises(TypeError):
            debugger("/bin/ls", env=12345)

        # Ensure that we cannot set env to a non-dictionary type
        with self.assertRaises(TypeError):
            debugger("/bin/ls", env=["A=B"])

        # Ensure that we cannot set env with non-string keys or values
        d = debugger("/bin/ls", env={"A": "B"})
        with self.assertRaises(TypeError):
            d.env[123] = "C"
        with self.assertRaises(TypeError):
            d.env["D"] = 456
        d.terminate()

        # Ensure that non-string keys or values are not allowed in the call to
        # debugger
        with self.assertRaises(TypeError):
            debugger("/bin/ls", env={123: "C"})
        with self.assertRaises(TypeError):
            debugger("/bin/ls", env={"D": 456})

    def test_envdict_copy(self):
        # We check that instancing the debugger with a dict copies it
        env = {"A": "B", "C": "D"}
        d = debugger("/bin/ls", env=env)
        self.assertEqual(d.env, env)
        env["E"] = "F"
        self.assertNotEqual(d.env, env)
        self.assertEqual(d.env, {"A": "B", "C": "D"})
        d.terminate()