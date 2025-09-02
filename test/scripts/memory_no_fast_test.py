#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import ctypes
from pwn import process
from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE, base_of
from utils.thread_utils import FUN_ARG_0

from libdebug import debugger, libcontext
from libdebug.utils.platform_utils import get_platform_gp_register_size


class MemoryNoFastTest(TestCase):
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
        d = debugger(RESOLVE_EXE("memory_test"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test"), fast_memory=False)

        d.run()

        bp = d.breakpoint("change_memory")

        d.cont()

        # This should not raise an exception
        file = d.memory[0x0, 256]

        # File should start with ELF magic number
        self.assertTrue(file.startswith(b"\x7fELF"))
        
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
        d = debugger(RESOLVE_EXE("memory_test"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test_2"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test_2"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test_2"), fast_memory=False)

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

    def test_memory_large_read(self):
        d = debugger(RESOLVE_EXE("memory_test_3"), fast_memory=False)

        d.run()

        bp = d.bp("do_nothing")

        d.cont()

        assert bp.hit_on(d)

        leak = FUN_ARG_0(d)

        # Read 256K of memory
        data = d.memory[leak, 256 * 1024]

        assert data == b"".join(x.to_bytes(4, "little") for x in range(64 * 1024))

        d.kill()
        d.terminate()

    def test_invalid_memory_locations(self):
        d = debugger(RESOLVE_EXE("memory_test"), fast_memory=False)

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
        d = debugger(RESOLVE_EXE("memory_test_4"), fast_memory=False)

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

    def test_memory_mixed_access(self):
        d = debugger(RESOLVE_EXE("memory_test_2"), fast_memory=True)

        d.run()

        base = base_of(d)

        # Test different ways to access memory at the start of the file
        file_0 = d.memory[base, 256]
        d.fast_memory = False
        file_1 = d.memory[0x0, 256]
        d.fast_memory = True
        file_2 = d.memory[0x0:0x100]
        d.fast_memory = False
        file_3 = d.memory[0x0:0x100]

        self.assertEqual(file_0, file_1)
        self.assertEqual(file_0, file_2)
        self.assertEqual(file_0, file_3)

        for _ in range(3):
            d.step()

        d.fast_memory = False
        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.fast_memory = True
        self.assertEqual(d.memory[base, 8], b"abcd1234")
        d.memory[base] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.assertEqual(d.memory[base, 8], b"\x01\x02\x03\x04\x05\x06\x07\x08")

        d.fast_memory = False
        self.assertEqual(d.memory[base, 8], b"\x01\x02\x03\x04\x05\x06\x07\x08")
        d.memory[base] = b"abcd1234"
        self.assertEqual(d.memory[base, 8], b"abcd1234")

        d.kill()
        d.terminate()

    def test_memory_attach(self):
        # Ensure that slow memory works when attaching to a process
        r = process(RESOLVE_EXE("attach_test"), env={})

        d = debugger(fast_memory=False)

        d.attach(r.pid)

        self.assertEqual(d.memory[0x0, 4, "binary"], b"\x7fELF")

        d.kill()
        d.terminate()

        r.close()
        del r
    
    def test_memory_no_fast_debugger_status(self):
        d = debugger(RESOLVE_EXE("basic_test"), fast_memory=False)
        
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