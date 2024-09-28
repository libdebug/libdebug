#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from subprocess import Popen, PIPE
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE


class RunPipesTest(TestCase):
    def test_binary_proxy(self):
        unpatched = Popen([RESOLVE_EXE("run_pipes_test")], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        buffer = b""
        while b"1." not in buffer:
            buffer += unpatched.stdout.read(1)

        # Option 1 should print the flag
        unpatched.stdin.write(b"1\n")
        unpatched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += unpatched.stdout.read(1)
        self.assertIn(b"flag{provola}", buffer)

        # Option 2 should print the flag after the admin mode check
        unpatched.stdin.write(b"2\n")
        unpatched.stdin.flush()
        unpatched.stdin.write(b"admin\n")
        unpatched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += unpatched.stdout.read(1)
        self.assertIn(b"flag{provola}", buffer)

        # Option 3 should print the flag after the signal handler
        unpatched.stdin.write(b"3\n")
        unpatched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += unpatched.stdout.read(1)
        self.assertIn(b"flag{provola}", buffer)

        # Exit
        unpatched.stdin.write(b"4\n")
        unpatched.stdin.flush()

        unpatched.kill()

        patched = Popen(["python3", "scripts/run_pipes_test_script.py", RESOLVE_EXE("run_pipes_test")], stdin=PIPE, stdout=PIPE, stderr=PIPE)

        buffer = b""
        while b"1." not in buffer:
            buffer += patched.stdout.read(1)

        # Option 1 should print not the flag
        patched.stdin.write(b"1\n")
        patched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += patched.stdout.read(1)
        self.assertIn(b"flag{nahmate}", buffer)

        # Option 2 should not print the flag after the admin mode check
        patched.stdin.write(b"2\n")
        patched.stdin.flush()
        patched.stdin.write(b"admin\n")
        patched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += patched.stdout.read(1)
        self.assertIn(b"Wrong password", buffer)

        # Option 3 should not print the flag after the signal handler
        patched.stdin.write(b"3\n")
        patched.stdin.flush()

        buffer = b""
        while b"1." not in buffer:
            buffer += patched.stdout.read(1)
        self.assertIn(b"SIGPROVOLA", buffer)

        # Exit
        patched.stdin.write(b"4\n")
        patched.stdin.flush()

        patched.kill()
