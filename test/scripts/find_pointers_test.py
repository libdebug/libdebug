#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import PLATFORM, BASE, RESOLVE_EXE

from libdebug import debugger
from libdebug.utils.libcontext import libcontext


match PLATFORM:
    case "amd64":
        LOCATION = 0x12c4
    case "aarch64":
        LOCATION = 0xa54
    case "i386":
        LOCATION = 0x12be
    case _:
        raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")
    
class FindPointersTest(TestCase):
    def test_find_ref_strings(self):
        d = debugger(RESOLVE_EXE("find_ptr_test"))
        
        r = d.run()
        d.bp(LOCATION, hardware=True, file="binary")

        d.cont()

        # Find references to the stack in the heap
        values = d.mem.find_pointers("stack", "heap")

        d.cont()

        # Check the values
        self.assertEqual(len(values), 3)
        
        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)

        self.assertEqual(correct_reference, values[0][0])
        self.assertEqual(correct_source, values[0][1])

        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)
        
        self.assertEqual(correct_reference, values[1][0])
        self.assertEqual(correct_source, values[1][1])
        
        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)
        
        self.assertEqual(correct_reference, values[2][0])
        self.assertEqual(correct_source, values[2][1])
        
        d.wait()

        d.kill()
        
    def test_find_ref_addresses(self):
        d = debugger(RESOLVE_EXE("find_ptr_test"))
        
        r = d.run()
        d.bp(LOCATION, hardware=True, file="binary")

        d.cont()

        # Find references to the stack in the heap
        heap_base = d.maps.filter("heap")[0].start
        stack_base = d.maps.filter("stack")[0].start
        values = d.mem.find_pointers(stack_base, heap_base)

        d.cont()

        # Check the values
        self.assertEqual(len(values), 3)
        
        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)

        self.assertEqual(correct_reference, values[0][0])
        self.assertEqual(correct_source, values[0][1])

        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)
        
        self.assertEqual(correct_reference, values[1][0])
        self.assertEqual(correct_source, values[1][1])
        
        correct_values = r.recvline().strip().split(b" ")
        correct_reference = int(correct_values[0], 16)
        correct_source = int(correct_values[1], 16)
        
        self.assertEqual(correct_reference, values[2][0])
        self.assertEqual(correct_source, values[2][1])
        
        d.wait()

        d.kill()
                
        
        