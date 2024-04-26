#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest
import io
import sys

from libdebug import debugger


class SyscallHijackTest(unittest.TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__
    
    
    def test_hijack_syscall(self):
        def on_enter_write(d, syscall_number):
            nonlocal write_count
                        
            write_count += 1

        d = debugger("binaries/syscall_hook_test")

        write_count = 0
        r = d.run()

        d.hijack_syscall("getcwd", "write")

        # Hook hijack is on, we expect the write hook to be called three times
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 3)

        write_count = 0
        r = d.run()
        
        d.hijack_syscall("getcwd", "write", hook_hijack=False)
                
        # Hook hijack is off, we expect the write hook to be called only twice
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 2)
    
    def test_hijack_syscall_with_pprint(self):
        def on_enter_write(d, syscall_number):
            nonlocal write_count
            
            write_count += 1

        d = debugger("binaries/syscall_hook_test")

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.hijack_syscall("getcwd", "write")

        # Hook hijack is on, we expect the write hook to be called three times
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 3)

        write_count = 0
        r = d.run()
        
        d.pprint_syscalls = True
        d.hijack_syscall("getcwd", "write", hook_hijack=False)
                
        # Hook hijack is off, we expect the write hook to be called only twice
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 2)
        
    def test_hijack_syscall_hook(self):
        def on_enter_write(d, syscall_number):
            nonlocal write_count

            write_count += 1
            
        def on_enter_getcwd(d, syscall_number):
            d.syscall_number = 0x1

        d = debugger("binaries/syscall_hook_test")

        write_count = 0
        r = d.run()

        d.hook_syscall("getcwd", on_enter=on_enter_getcwd)

        # Hook hijack is on, we expect the write hook to be called three times
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 3)

        write_count = 0
        r = d.run()
        
        d.hook_syscall("getcwd", on_enter=on_enter_getcwd, hook_hijack=False)
                
        # Hook hijack is off, we expect the write hook to be called only twice
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 2)
    
    
    def test_hijack_syscall_hook_with_pprint(self):
        def on_enter_write(d, syscall_number):
            nonlocal write_count

            write_count += 1
            
        def on_enter_getcwd(d, syscall_number):
            d.syscall_number = 0x1

        d = debugger("binaries/syscall_hook_test")

        write_count = 0
        r = d.run()

        d.pprint_syscalls = True
        d.hook_syscall("getcwd", on_enter=on_enter_getcwd)

        # Hook hijack is on, we expect the write hook to be called three times
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 3)

        write_count = 0
        r = d.run()
        
        d.pprint_syscalls = True
        d.hook_syscall("getcwd", on_enter=on_enter_getcwd, hook_hijack=False)
                
        # Hook hijack is off, we expect the write hook to be called only twice
        hook2 = d.hook_syscall("write", on_enter=on_enter_write)

        r.sendline(b"provola")

        d.cont()

        d.kill()

        self.assertEqual(write_count, hook2.hit_count)
        self.assertEqual(hook2.hit_count, 2)

    def loop_detection_test(self):
        d = debugger("binaries/syscall_hook_test")

        r = d.run()
        d.hijack_syscall("getcwd", "write")
        d.hijack_syscall("write", "getcwd")
        r.sendline(b"provola")

        # We expect an exception to be raised
        with self.assertRaises(RuntimeError):
            d.cont()
            d.wait()
            d.kill()

        r = d.run()
        d.hijack_syscall("getcwd", "write", hook_hijack=False)
        d.hijack_syscall("write", "getcwd")
        r.sendline(b"provola")

        # We expect no exception to be raised
        d.cont()

        r = d.run()
        d.hijack_syscall("getcwd", "write")
        d.hijack_syscall("write", "getcwd", hook_hijack=False)
        r.sendline(b"provola")

        # We expect no exception to be raised
        d.cont()

if __name__ == "__main__":
    unittest.main()