#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import ctypes
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE, base_of
from utils.thread_utils import FUN_ARG_0, STACK_POINTER

from libdebug import debugger
from libdebug.utils.libcontext import libcontext
from libdebug.utils.platform_utils import get_platform_gp_register_size


class MemoryTest(TestCase):
    def setUp(self) -> None:
        # Redirect logging to a string buffer
        self.log_capture_string = io.StringIO()
        self.log_handler = logging.StreamHandler(self.log_capture_string)
        self.log_handler.setLevel(logging.WARNING)

        self.logger = logging.getLogger("libdebug")
        self.original_handlers = self.logger.handlers
        self.logger.handlers = []
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.WARNING)

    def tearDown(self):
        # Remove the custom handler
        self.logger.removeHandler(self.log_handler)

        # Restore the original handlers
        self.logger.handlers = self.original_handlers

        # Close the log capture string buffer
        self.log_capture_string.close()

    def test_memory(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        assert d.instruction_pointer == bp.address

        address = FUN_ARG_0(d)
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)

        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)

        d.kill()
        d.terminate()

    def test_mem_access_libs(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.breakpoint("leak_address")

        d.cont()

        assert d.instruction_pointer == bp.address

        address = FUN_ARG_0(d)
        with libcontext.tmp(sym_lvl=5):
            arena = d.memory["main_arena", 256, "libc"]

        def pack(x):
            return x.to_bytes(get_platform_gp_register_size(d.arch), "little")

        self.assertTrue(pack(address - get_platform_gp_register_size(d.arch) * 2) in arena)

        d.kill()
        d.terminate()

    def test_memory_exceptions(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        # This should not raise an exception
        file = d.memory[0x0, 256]
        
        # The following commands should raise exceptions
        with self.assertRaises(TypeError) as cm:
            d.memory[0x0, ctypes.c_uint32(10)]
        self.assertIn("Invalid type for the size", str(cm.exception))
        
        with self.assertRaises(TypeError) as cm:
            d.memory[ctypes.c_uint32(0x0), 256]
        self.assertIn("Invalid type for the address", str(cm.exception))
        
        with self.assertRaises(TypeError) as cm:
            d.memory[0x0, 256, 0xff]
        self.assertIn("Invalid type for the backing file", str(cm.exception))
        
        with self.assertRaises(ValueError) as cm:
            d.memory[0x0, 256, "invalid"]
        self.assertIn("No memory maps available to resolve the address", str(cm.exception))
        
        with self.assertRaises(TypeError) as cm:
            d.memory[0x0, ctypes.c_uint32(10)] = b"abcd1234"
        self.assertIn("Invalid type for the size", str(cm.exception))
        
        with self.assertRaises(TypeError) as cm:
            d.memory[ctypes.c_uint32(0x0), 256] = b"abcd1234"
        self.assertIn("Invalid type for the address", str(cm.exception))
        
        with self.assertRaises(TypeError) as cm:
            d.memory[0x0, 256, 0xff] = b"abcd1234"
        self.assertIn("Invalid type for the backing file", str(cm.exception))
        
        with self.assertRaises(ValueError) as cm:
            d.memory[0x0, 256, "invalid"] = b"abcd1234"
        self.assertIn("No memory maps available to resolve the address", str(cm.exception))

        # File should start with ELF magic number
        self.assertTrue(file.startswith(b"\x7fELF"))

        assert d.instruction_pointer == bp.address

        address = FUN_ARG_0(d)
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)

        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)

        d.kill()
        d.terminate()

    def test_memory_multiple_runs(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        for _ in range(10):
            d.run()

            bp = d.breakpoint("change_memory")

            d.cont()

            assert d.instruction_pointer == bp.address

            address = FUN_ARG_0(d)
            prev = bytes(range(256))

            self.assertTrue(d.memory[address, 256] == prev)

            d.memory[address + 128 :] = b"abcd123456"
            prev = prev[:128] + b"abcd123456" + prev[138:]

            self.assertTrue(d.memory[address : address + 256] == prev)

            d.kill()

        d.terminate()

    def test_memory_access_while_running(self):
        d = debugger(RESOLVE_EXE("memory_test_2"))

        d.run()

        bp = d.breakpoint("do_nothing")

        d.cont()

        # Verify that memory access is only possible when the process is stopped
        value = int.from_bytes(d.memory["state", 8], "little")
        self.assertEqual(value, 0xDEADBEEF)
        self.assertEqual(d.instruction_pointer, bp.address)

        d.kill()
        d.terminate()

    def test_memory_access_methods(self):
        d = debugger(RESOLVE_EXE("memory_test_2"))

        d.run()

        base = base_of(d)

        # Test different ways to access memory at the start of the file
        file_0 = d.memory[base, 256]
        file_1 = d.memory[0x0, 256]
        file_2 = d.memory[0x0:0x100]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_0, file_2)

        # Validate that the length of the read bytes is correct
        file_0 = d.memory[0x0]
        file_1 = d.memory[base]

        self.assertEqual(file_0, file_1)
        self.assertEqual(len(file_0), 1)

        # Validate that slices work correctly
        file_0 = d.memory[0x0:"do_nothing"]
        file_1 = d.memory[base:"do_nothing"]

        self.assertEqual(file_0, file_1)

        self.assertRaises(ValueError, lambda: d.memory[0x1000:0x0])
        # _fini is after main
        self.assertRaises(ValueError, lambda: d.memory["_fini":"main"])

        # Test different ways to write memory
        d.memory[0x0, 8] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8], b"abcd1234")

        d.memory[0x0, 8] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[base:] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.memory[base:] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.memory[base] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8], b"abcd1234")

        d.memory[0x0, 8] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.memory["main":] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.memory["main"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8], b"abcd1234")

        d.kill()
        d.terminate()

    def test_memory_access_methods_backing_file(self):
        d = debugger(RESOLVE_EXE("memory_test_2"))

        d.run()

        base = base_of(d)

        # Validate that slices work correctly
        file_0 = d.memory[0x0:"do_nothing", "binary"]
        file_1 = d.memory[0x0:"do_nothing", "memory_test_2"]
        file_2 = d.memory[base:"do_nothing", "binary"]
        file_3 = d.memory[base:"do_nothing", "memory_test_2"]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_1, file_2)
        self.assertEqual(file_2, file_3)

        # Test different ways to write memory
        d.memory[0x0, 8, "binary"] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0, 8, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory[0x0, 8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8, "binary"] = b"abcd1234"
        self.assertEqual(d.memory[0x0:8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory[0x0:0x8, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory[0x0:8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":, "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory["main":, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":, "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory["main":, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main", "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main", "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main", 8, "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "memory_test_2"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "binary"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "binary"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "memory_test_2"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "memory_test_2"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        d.memory["main":"main+8", "hybrid"] = b"abcd1234"
        self.assertEqual(d.memory["main":"main+8", "hybrid"], b"abcd1234")

        d.memory[0x0, 8, "binary"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(ValueError):
            d.memory["main":"main+8", "absolute"] = b"abcd1234"

        d.kill()
        d.terminate()
    
    def test_search_maps(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.breakpoint("leak_address")

        d.cont()

        assert d.instruction_pointer == bp.address
        
        maps = d.maps.filter("memory_test")
        
        for vmap in maps:
            self.assertIn(RESOLVE_EXE("memory_test"), vmap.backing_file)
            
        maps_bin = d.maps.filter("binary")
        
        for vmap in maps_bin:
            self.assertIn(RESOLVE_EXE("memory_test"), vmap.backing_file)
            
        self.assertEqual(maps, maps_bin)
        
        maps = d.maps.filter("libc")
        
        for vmap in maps:
            self.assertIn("libc", vmap.backing_file)
            
        maps = d.maps.filter(STACK_POINTER(d))
        
        for vmap in maps:
            self.assertIn("stack", vmap.backing_file)
            
        d.kill()
        d.terminate()

    def test_memory_large_read(self):
        d = debugger(RESOLVE_EXE("memory_test_3"))

        d.run()

        bp = d.bp("do_nothing")

        d.cont()

        assert bp.hit_on(d)

        leak = FUN_ARG_0(d)

        # Read 4MB of memory
        data = d.memory[leak, 4 * 1024 * 1024]

        assert data == b"".join(x.to_bytes(4, "little") for x in range(1024 * 1024))

        d.kill()
        d.terminate()

    def test_invalid_memory_locations(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.bp("change_memory")

        d.cont()

        assert d.instruction_pointer == bp.address

        address = 0xDEADBEEF # This address does not exist in the given binary

        with self.assertRaises(ValueError):
            d.memory[address, 256, "absolute"]

        with self.assertRaises(ValueError):
            d.memory[address, 256, "absolute"] = b"abcd1234"

        address = 0xDEADBEEFD00DDEADBEEF # This address is out of bounds on any platform

        with self.assertRaises(ValueError):
            d.memory[address, 256, "absolute"]

        with self.assertRaises(ValueError):
            d.memory[address, 256, "absolute"] = b"abcd1234"

        d.kill()
        d.terminate()

    def test_memory_multiple_threads(self):
        d = debugger(RESOLVE_EXE("memory_test_4"))

        d.run()

        leaks = []
        leak_addresses = []

        def leak(t, _):
            leaks.append(t.memory[FUN_ARG_0(t), 16])
            leak_addresses.append(FUN_ARG_0(t))

        d.bp("leak", callback=leak, hardware=True)
        exit = d.bp("before_exit", hardware=True)

        d.cont()
        d.wait()

        assert exit.hit_on(d)

        for i in range(8):
            assert (chr(i).encode("latin-1") * 16) in leaks

        leaks = [d.memory[x, 16] for x in leak_addresses]

        # threads are stopped, check we correctly read the memory
        for i in range(8):
            assert (chr(i).encode("latin-1") * 16) in leaks

        d.kill()
        d.terminate()

    def test_search_memory(self):
        d = debugger(RESOLVE_EXE("memory_test"))

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        assert d.instruction_pointer == bp.address

        address = FUN_ARG_0(d)
        prev = bytes(range(256))

        self.assertTrue(d.memory[address, 256] == prev)
        
        d.memory[address + 128 :] = b"abcd123456"
        prev = prev[:128] + b"abcd123456" + prev[138:]

        self.assertTrue(d.memory[address : address + 256] == prev)
        
        start = d.maps.filter("heap")[0].start
        end = d.maps.filter("heap")[-1].end - 1
        
        # Search for the string "abcd123456" in the whole memory
        self.assertTrue(d.memory.find(b"abcd123456") == [address + 128])
        
        # Search for the string "abcd123456" in the memory starting from start
        self.assertTrue(d.memory.find(b"abcd123456", start=start) == [address + 128])
        
        # Search for the string "abcd123456" in the memory ending at end
        self.assertTrue(d.memory.find(b"abcd123456", end=end) == [address + 128])
        
        # Search for the string "abcd123456" in the heap using backing file
        self.assertTrue(d.memory.find(b"abcd123456", file="heap") == [address + 128])
        
        # Search for the string "abcd123456" in the heap using start and end
        self.assertTrue(d.memory.find(b"abcd123456", start=start, end=end) == [address + 128])
        
        with self.assertRaises(ValueError) as cm:
            d.memory.find(b"abcd123456", file="invalid")
        self.assertIn("No memory map found for the specified backing file", str(cm.exception))

        d.kill()
        d.terminate()
    
    def test_memory_debugger_status(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        
        with self.assertRaises(RuntimeError):
            d.memory
            
        with self.assertRaises(RuntimeError):
            d.mem

        d.run()   
        
        d.memory
             
        d.detach()
        
        with self.assertRaises(RuntimeError):
            d.memory
            
        with self.assertRaises(RuntimeError):
            d.mem
        
        d.terminate()

    def test_telescope_depth(self):
        d = debugger(RESOLVE_EXE("telescope_test"))
    
        r = d.run()

        d.cont()

        str_five_levels = int(r.recvline(), 16)
        str_fifteen_levels = int(r.recvline(), 16)
        int_five_levels = int(r.recvline(), 16)
        int_fifteen_levels = int(r.recvline(), 16)

        d.interrupt()
        
        ### 5 levels with a final string
        # Test telescope with default depth
        str_five_levels_default = d.mem.telescope(str_five_levels)
        self.assertEqual(len(str_five_levels_default), 6)
        self.assertIsInstance(str_five_levels_default[-1], str)
        self.assertEqual(str_five_levels_default[-1], "Telescope test passed!")
        self.assertEqual(str_five_levels_default[0], str_five_levels)
        
        # Test telescope with the right, custom depth
        str_five_levels_len = d.mem.telescope(str_five_levels, 6)
        self.assertEqual(str_five_levels_default, str_five_levels_len)
        
        # Test telescope with the wrong, custom depth
        str_five_levels_wrong = d.mem.telescope(str_five_levels, 78)
        self.assertEqual(str_five_levels_default, str_five_levels_wrong)
        
        ### 15 levels with a final string
        # Test telescope with default depth. This will return only the first 10 levels + the original value
        str_fifteen_levels_default = d.mem.telescope(str_fifteen_levels)
        self.assertEqual(len(str_fifteen_levels_default), 11)
        self.assertIsInstance(str_fifteen_levels_default[-1], int)
        
        # Test telescope with the right, custom depth
        str_fifteen_levels_len = d.mem.telescope(str_fifteen_levels, 16)
        self.assertEqual(len(str_fifteen_levels_len), 16)
        self.assertIsInstance(str_fifteen_levels_len[-1], str)
        self.assertEqual(str_fifteen_levels_default, str_fifteen_levels_len[:11])
        self.assertEqual(str_fifteen_levels_len[-1], "Telescope test passed!")
        
        # Test telescope with the wrong, custom depth
        str_fifteen_levels_wrong = d.mem.telescope(str_fifteen_levels, 78)
        self.assertEqual(str_fifteen_levels_wrong, str_fifteen_levels_len)
        
        ### 5 levels with a final integer
        # Test telescope with default depth
        int_five_levels_default = d.mem.telescope(int_five_levels, min_str_len=6)
        self.assertEqual(len(int_five_levels_default), 6)
        self.assertIsInstance(int_five_levels_default[-1], int)
        self.assertEqual(int_five_levels_default[-1], 4242)
        
        # Test telescope with the right, custom depth
        int_five_levels_len = d.mem.telescope(int_five_levels, 6, min_str_len=6)
        self.assertEqual(int_five_levels_default, int_five_levels_len)
        
        # Test telescope with the wrong, custom depth
        int_five_levels_wrong = d.mem.telescope(int_five_levels, 78, min_str_len=6)
        self.assertEqual(int_five_levels_default, int_five_levels_wrong)
        
        ### 15 levels with a final integer
        # Test telescope with default depth. This will return only the first 10 levels + the original value
        int_fifteen_levels_default = d.mem.telescope(int_fifteen_levels, min_str_len=6)
        self.assertEqual(len(int_fifteen_levels_default), 11)
        self.assertIsInstance(int_fifteen_levels_default[-1], int)
        self.assertNotEqual(int_fifteen_levels_default[-1], 4242)
        
        # Test telescope with the right, custom depth
        int_fifteen_levels_len = d.mem.telescope(int_fifteen_levels, 16, min_str_len=6)
        self.assertEqual(len(int_fifteen_levels_len), 16)
        self.assertIsInstance(int_fifteen_levels_len[-1], int)
        self.assertEqual(int_fifteen_levels_default, int_fifteen_levels_len[:11])
        self.assertEqual(int_fifteen_levels_len[-1], 4242)
        
        # Test telescope with the wrong, custom depth
        int_fifteen_levels_wrong = d.mem.telescope(int_fifteen_levels, 78, min_str_len=6)
        self.assertEqual(int_fifteen_levels_wrong, int_fifteen_levels_len)
        
        # Test telescope with a depth of 0
        with self.assertRaises(ValueError) as cm:
            d.mem.telescope(str_five_levels, 0)
        self.assertIn("depth must be greater than 0.", str(cm.exception))
        
        d.wait()

        d.kill()
        d.terminate()
    
    
    def test_telescope_loop(self):
        d = debugger(RESOLVE_EXE("telescope_test"))
    
        r = d.run()

        d.cont()

        for _ in range(4):
            r.recvline()  # Skip the first lines
        loop_start = int(r.recvline(), 16)

        d.interrupt()
        
        self.log_capture_string.truncate(0)
        self.log_capture_string.seek(0)
        
        chain_loop = d.mem.telescope(loop_start)
        logged = self.log_capture_string.getvalue()
        self.assertIn("WARNING", logged)
        self.assertIn("The telescope chain contains a loop", logged)
        self.assertIsInstance(chain_loop[-1], int)
        self.assertEqual(len(chain_loop), 11)
        
        self.log_capture_string.truncate(0)
        self.log_capture_string.seek(0)
        
        chain_loop = d.mem.telescope(loop_start, 100)
        logged = self.log_capture_string.getvalue()
        self.assertIn("WARNING", logged)
        self.assertIn("The telescope chain contains a loop", logged)
        self.assertIsInstance(chain_loop[-1], int)
        self.assertEqual(len(chain_loop), 101)
        

        d.wait()

        d.kill()
        d.terminate()
        
    def test_telescope_str_len(self):
        d = debugger(RESOLVE_EXE("telescope_test"))
    
        r = d.run()

        d.cont()

        str_five_levels = int(r.recvline(), 16)

        d.interrupt()
        
        # Test telescope with default str length values
        str_five_levels_content = d.mem.telescope(str_five_levels)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!")
        
        # Test telescope with a lower, custom min str length
        str_five_levels_content = d.mem.telescope(str_five_levels, min_str_len=5)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!")

        # Test telescope with a higher, custom min str length
        # This will make impossible to interpret the last value as a string
        str_five_levels_content = d.mem.telescope(str_five_levels, min_str_len=100)
        self.assertIsInstance(str_five_levels_content[-1], int)

        # Test telescope with a higher, custom max str length
        str_five_levels_content = d.mem.telescope(str_five_levels, max_str_len=30)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!")
        
        # Test telescope with a lower, custom max str length
        str_five_levels_content = d.mem.telescope(str_five_levels, max_str_len=10)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!"[:10])
        
        # Test telescope with -1 as min str length
        # This will make the telescope to not interpret the last value as a string
        str_five_levels_content = d.mem.telescope(str_five_levels, min_str_len=-1)
        self.assertIsInstance(str_five_levels_content[-1], int)
        
        # Test telescope with min str length equal to max str length
        str_five_levels_content = d.mem.telescope(str_five_levels, min_str_len=6, max_str_len=6)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!"[:6])
        
        # Test telescope with 0 as min str length
        str_five_levels_content = d.mem.telescope(str_five_levels, min_str_len=0)
        self.assertIsInstance(str_five_levels_content[-1], str)
        self.assertEqual(str_five_levels_content[-1], "Telescope test passed!")
        
        # Test telescope with min str length greater than max str length
        with self.assertRaises(ValueError) as cm:
            d.mem.telescope(str_five_levels, min_str_len=10, max_str_len=5)
        self.assertIn("min_str_len must be less than or equal to max_str_len.", str(cm.exception))
        
        # Test telescope with min str length lower than -1
        with self.assertRaises(ValueError) as cm:
            d.mem.telescope(str_five_levels, min_str_len=-2)
        self.assertIn("min_str_len must be -1 or greater.", str(cm.exception))
        
        # Test telescope with max str length lower than 1
        with self.assertRaises(ValueError) as cm:
            d.mem.telescope(str_five_levels, max_str_len=0)
        self.assertIn("max_str_len must be greater than 0.", str(cm.exception))

        d.wait()

        d.kill()
        d.terminate()