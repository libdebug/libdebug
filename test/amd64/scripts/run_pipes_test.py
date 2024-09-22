#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from pwn import process


class RunPipesTest(unittest.TestCase):
    def test_binary_proxy(self):
        unpatched = process("binaries/run_pipes_test")

        unpatched.recvuntil(b"1.")

        # Option 1 should print the flag
        unpatched.sendline(b"1")
        self.assertIn(b"flag{provola}", unpatched.recvuntil(b"1."))

        # Option 2 should print the flag after the admin mode check
        unpatched.sendline(b"2")
        unpatched.sendline(b"admin")
        self.assertIn(b"flag{provola}", unpatched.recvuntil(b"1."))

        # Option 3 should print the flag after the signal handler
        unpatched.sendline(b"3")
        self.assertIn(b"flag{provola}", unpatched.recvuntil(b"1."))

        # Exit
        unpatched.sendline(b"4")

        unpatched.kill()

        patched = process(["python3", "scripts/run_pipes_test_script.py"])

        patched.recvuntil(b"1.")

        # Option 1 should print not the flag
        patched.sendline(b"1")
        self.assertIn(b"flag{nahmate}", patched.recvuntil(b"1."))

        # Option 2 should not print the flag after the admin mode check
        patched.sendline(b"2")
        patched.sendline(b"admin")
        self.assertIn(b"Wrong password", patched.recvuntil(b"1."))

        # Option 3 should not print the flag after the signal handler
        patched.sendline(b"3")
        self.assertIn(b"SIGPROVOLA", patched.recvuntil(b"1."))

        # Exit
        patched.sendline(b"4")

        patched.kill()