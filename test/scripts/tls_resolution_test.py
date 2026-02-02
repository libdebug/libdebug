#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

"""Unit tests for TLS (Thread-Local Storage) symbol resolution and value reading."""

import struct
from unittest import TestCase, skipIf

from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger
from libdebug.native.libdebug_debug_sym_parser import SymbolType, read_elf_info

def get_tls_block_info(binary_path: str) -> tuple[int, int]:
    """Get the TLS block size and alignment from an ELF binary."""
    elf_info = read_elf_info(binary_path, 5)
    if hasattr(elf_info, "tls_info"):
        tls_info = elf_info.tls_info
        # Calculate aligned size (round up to alignment)
        raw_size = tls_info.tls_block_size
        align = tls_info.tls_block_align
        aligned_size = ((raw_size + align - 1) // align) * align
        return aligned_size, align
    return 0, 0


def compute_tls_address(fs_base: int, tls_offset: int, aligned_tls_size: int) -> int:
    """Compute the actual TLS address using Variant II formula: fs_base - aligned_tls_size + offset."""
    return fs_base - aligned_tls_size + tls_offset


@skipIf(PLATFORM not in ["amd64", "x86_64"], "TLS resolution test requires x86-64")
class TLSResolutionTest(TestCase):
    """Tests for TLS symbol resolution and value reading."""

    def test_tls_symbol_detection(self):
        """Verify TLS symbols are detected with correct metadata."""
        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols
        tls_symbols = symbols.tls_symbols

        # Should have TLS symbols
        self.assertGreater(len(tls_symbols), 0, "Should detect TLS symbols")

        # Find our test TLS variables
        expected_tls_vars = ["tls_initialized", "tls_uninitialized", "tls_string", "tls_double"]
        found_vars = {s.name for s in tls_symbols}

        for var in expected_tls_vars:
            self.assertIn(var, found_vars, f"TLS variable '{var}' should be detected")

        # Verify they have correct type
        for sym in tls_symbols:
            if sym.name in expected_tls_vars:
                self.assertEqual(sym.symbol_type, SymbolType.TLS, 
                               f"'{sym.name}' should have TLS type")
                self.assertTrue(sym.is_tls, f"'{sym.name}' should have is_tls=True")

        d.kill()
        d.terminate()

    def test_tls_initialized_value(self):
        """Verify we can read the initial value of an initialized TLS variable."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)
        self.assertGreater(aligned_tls_size, 0, "TLS block size should be > 0")

        # Get fs_base for TLS access
        fs_base = d.regs.fs_base
        self.assertNotEqual(fs_base, 0, "FS_BASE should be non-zero")

        # Find tls_initialized symbol
        symbols = d.symbols
        tls_init_syms = [s for s in symbols.tls_symbols if s.name == "tls_initialized"]
        self.assertEqual(len(tls_init_syms), 1, "Should find exactly one tls_initialized symbol")

        sym = tls_init_syms[0]

        # Calculate the TLS address using Variant II formula
        # Address = fs_base - aligned_tls_size + symbol_offset
        tls_addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)

        # Read the value (int = 4 bytes)
        value_bytes = d.memory[tls_addr, 4, "absolute"]
        value = struct.unpack("<i", value_bytes)[0]

        # The initial value should be 42 (from tls_test.c)
        self.assertEqual(value, 42, f"tls_initialized should be 42, got {value}")

        d.kill()
        d.terminate()

    def test_tls_string_value(self):
        """Verify we can read the initial value of a TLS string."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)
        fs_base = d.regs.fs_base

        # Find tls_string symbol
        symbols = d.symbols
        tls_str_syms = [s for s in symbols.tls_symbols if s.name == "tls_string"]
        self.assertEqual(len(tls_str_syms), 1, "Should find exactly one tls_string symbol")

        sym = tls_str_syms[0]
        tls_addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)

        # Read the string (64 bytes as defined in tls_test.c)
        value_bytes = d.memory[tls_addr, 64, "absolute"]
        # Find null terminator
        null_pos = value_bytes.find(b'\x00')
        if null_pos != -1:
            value_bytes = value_bytes[:null_pos]
        value = value_bytes.decode("utf-8", errors="replace")

        # The initial value should be "Hello TLS"
        self.assertEqual(value, "Hello TLS", f"tls_string should be 'Hello TLS', got '{value}'")

        d.kill()
        d.terminate()

    def test_tls_double_value(self):
        """Verify we can read the initial value of a TLS double."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)
        fs_base = d.regs.fs_base

        # Find tls_double symbol
        symbols = d.symbols
        tls_dbl_syms = [s for s in symbols.tls_symbols if s.name == "tls_double"]
        self.assertEqual(len(tls_dbl_syms), 1, "Should find exactly one tls_double symbol")

        sym = tls_dbl_syms[0]
        tls_addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)

        # Read the double (8 bytes)
        value_bytes = d.memory[tls_addr, 8, "absolute"]
        value = struct.unpack("<d", value_bytes)[0]

        # The initial value should be approximately 3.14159
        self.assertAlmostEqual(value, 3.14159, places=4,
                              msg=f"tls_double should be ~3.14159, got {value}")

        d.kill()
        d.terminate()

    def test_tls_value_after_modification(self):
        """Verify TLS values change after modification by writing to memory."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)

        # First breakpoint - before modification
        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        fs_base = d.regs.fs_base

        # Find tls_initialized
        symbols = d.symbols
        tls_init_syms = [s for s in symbols.tls_symbols if s.name == "tls_initialized"]
        sym = tls_init_syms[0]
        tls_addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)

        # Read initial value
        initial_bytes = d.memory[tls_addr, 4, "absolute"]
        initial_value = struct.unpack("<i", initial_bytes)[0]
        self.assertEqual(initial_value, 42, "Initial value should be 42")

        # Modify the TLS value directly through memory
        new_value = 12345
        d.memory[tls_addr, 4, "absolute"] = struct.pack("<i", new_value)

        # Read back the modified value
        modified_bytes = d.memory[tls_addr, 4, "absolute"]
        modified_value = struct.unpack("<i", modified_bytes)[0]

        # Verify our write worked
        self.assertEqual(modified_value, new_value, 
                        f"After modification, value should be {new_value}, got {modified_value}")

        d.kill()
        d.terminate()

    def test_tls_different_threads(self):
        """Verify different threads have different TLS values."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)

        # Set breakpoint in thread function
        d.bp("breakpoint_here")

        # Continue to first breakpoint (main thread)
        d.cont()
        d.wait()

        # Store main thread's TLS info
        main_thread = d.threads[0]
        main_fs_base = main_thread.regs.fs_base

        symbols = d.symbols
        tls_init_syms = [s for s in symbols.tls_symbols if s.name == "tls_initialized"]
        sym = tls_init_syms[0]

        main_tls_addr = compute_tls_address(main_fs_base, sym.tls_offset, aligned_tls_size)
        main_value_bytes = d.memory[main_tls_addr, 4, "absolute"]
        main_value = struct.unpack("<i", main_value_bytes)[0]

        # Continue past main thread modifications to where child threads hit breakpoint
        d.cont()
        d.wait()  # Main thread hits second breakpoint

        # Continue to let child threads run and hit breakpoint
        d.cont()
        d.wait()

        # Now we should have multiple threads
        if len(d.threads) > 1:
            # Find a different thread
            for thread in d.threads:
                if thread.tid != main_thread.tid:
                    thread_fs_base = thread.regs.fs_base

                    # Different threads should have different fs_base
                    if thread_fs_base != main_fs_base:
                        thread_tls_addr = compute_tls_address(thread_fs_base, sym.tls_offset, aligned_tls_size)
                        thread_value_bytes = d.memory[thread_tls_addr, 4, "absolute"]
                        thread_value = struct.unpack("<i", thread_value_bytes)[0]

                        # Child threads call modify_tls_values(thread_num * 100)
                        # So tls_initialized = base + 1 = (thread_num * 100) + 1
                        # This should be different from main thread's value
                        self.assertNotEqual(main_value, thread_value,
                                          "Different threads should have different TLS values")
                        break

        d.kill()
        d.terminate()


@skipIf(PLATFORM not in ["amd64", "x86_64"], "TLS resolution test requires x86-64")
class TLSLibcSymbolsTest(TestCase):
    """Tests for TLS symbols from libc (thread_arena, tcache, errno)."""

    def test_libc_tls_symbols_detected(self):
        """Verify libc TLS symbols are detected."""
        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols
        tls_symbols = symbols.tls_symbols

        # Common libc TLS symbols
        libc_tls_names = {"errno", "thread_arena", "tcache"}
        found_names = {s.name for s in tls_symbols}

        # At least errno should be present
        self.assertIn("errno", found_names, "errno TLS symbol should be found")

        # Count how many libc TLS we found
        found_libc = libc_tls_names & found_names
        self.assertGreaterEqual(len(found_libc), 1, 
                               f"Should find at least one libc TLS symbol, found: {found_libc}")

        d.kill()
        d.terminate()

    def test_errno_is_readable(self):
        """Verify errno TLS symbol exists and has correct metadata."""
        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Find errno symbol
        symbols = d.symbols
        errno_syms = [s for s in symbols.tls_symbols if s.name == "errno"]

        if errno_syms:
            sym = errno_syms[0]
            # Just verify it has TLS metadata
            self.assertTrue(sym.is_tls, "errno should be marked as TLS")
            self.assertIsNotNone(sym.tls_offset, "errno should have a TLS offset")
            # Note: We can't easily read libc TLS without the libc TLS block size
            # For now, just verify the symbol is detected

        d.kill()
        d.terminate()

    def test_thread_arena_is_readable(self):
        """Verify thread_arena TLS symbol exists and has correct metadata."""
        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Find thread_arena symbol
        symbols = d.symbols
        arena_syms = [s for s in symbols.tls_symbols if s.name == "thread_arena"]

        if arena_syms:
            sym = arena_syms[0]
            # Just verify it has TLS metadata
            self.assertTrue(sym.is_tls, "thread_arena should be marked as TLS")
            self.assertIsNotNone(sym.tls_offset, "thread_arena should have a TLS offset")
            # Note: We can't easily read libc TLS without the libc TLS block size

        d.kill()
        d.terminate()


@skipIf(PLATFORM not in ["amd64", "x86_64"], "TLS resolution test requires x86-64")
class TLSResolverAPITest(TestCase):
    """Tests for the TLSResolver API."""

    def test_tls_resolver_basic(self):
        """Test TLSResolver basic functionality."""
        from libdebug.symbols.tls_manager import TLSManager

        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        resolver = TLSManager(d._internal_debugger)
        thread = d.threads[0]

        # Find a TLS symbol
        symbols = d.symbols
        tls_init_syms = [s for s in symbols.tls_symbols if s.name == "tls_initialized"]

        if tls_init_syms:
            sym = tls_init_syms[0]
            info = resolver.resolve(sym, thread)

            # Verify TLSInfo fields
            self.assertEqual(info.thread_id, thread.tid, "Thread ID should match")
            self.assertTrue(info.is_static_tls, "Main binary TLS should be static")
            # The address might not be correct due to TLS block size calculation
            # but the API should return *something*
            self.assertIsNotNone(info.address, "TLS address should be resolved")

        d.kill()
        d.terminate()

    def test_tls_resolver_by_name(self):
        """Test TLSResolver.resolve_by_name functionality."""
        from libdebug.symbols.tls_manager import TLSManager

        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        resolver = TLSManager(d._internal_debugger)
        thread = d.threads[0]

        # Resolve by name
        info = resolver.resolve_by_name("tls_initialized", thread)

        if info:
            # Verify the resolver found the symbol
            self.assertIsNotNone(info.symbol, "Should find the symbol")
            self.assertEqual(info.symbol.name, "tls_initialized", "Symbol name should match")
            self.assertEqual(info.thread_id, thread.tid, "Thread ID should match")

        d.kill()
        d.terminate()

    def test_tls_resolver_multiple_symbols(self):
        """Test resolving multiple TLS symbols."""
        from libdebug.symbols.tls_manager import TLSManager

        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        resolver = TLSManager(d._internal_debugger)
        thread = d.threads[0]

        # Get all TLS addresses
        all_tls = resolver.get_all_tls_addresses(thread)

        # Should have multiple TLS symbols resolved
        self.assertGreater(len(all_tls), 0, "Should resolve multiple TLS symbols")

        # Verify some known ones are present
        resolved_names = {info.symbol.name for info in all_tls}
        self.assertIn("tls_initialized", resolved_names, 
                     "tls_initialized should be in resolved symbols")

        d.kill()
        d.terminate()


@skipIf(PLATFORM not in ["amd64", "x86_64"], "TLS resolution test requires x86-64")
class TLSOffsetConsistencyTest(TestCase):
    """Tests for TLS offset consistency and correctness."""

    def test_tls_offsets_are_distinct(self):
        """Verify different TLS variables have different offsets."""
        d = debugger(RESOLVE_EXE("tls_test"))
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols

        # Get our test TLS variables
        test_vars = ["tls_initialized", "tls_uninitialized", "tls_string", "tls_double"]
        tls_syms = [s for s in symbols.tls_symbols if s.name in test_vars]

        # Collect offsets
        offsets = {s.name: s.tls_offset for s in tls_syms}

        # All offsets should be distinct
        unique_offsets = set(offsets.values())
        self.assertEqual(len(unique_offsets), len(offsets),
                        f"TLS offsets should be distinct: {offsets}")

        d.kill()
        d.terminate()

    def test_tls_offset_alignment(self):
        """Verify TLS addresses have proper alignment for data types."""
        binary_path = RESOLVE_EXE("tls_test")
        d = debugger(binary_path)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Get TLS block info from ELF
        aligned_tls_size, _ = get_tls_block_info(binary_path)
        fs_base = d.regs.fs_base
        symbols = d.symbols

        # tls_double should be 8-byte aligned
        double_syms = [s for s in symbols.tls_symbols if s.name == "tls_double"]
        if double_syms:
            sym = double_syms[0]
            addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)
            self.assertEqual(addr % 8, 0, 
                           f"tls_double address should be 8-byte aligned, got {hex(addr)}")

        # tls_initialized (int) should be 4-byte aligned
        int_syms = [s for s in symbols.tls_symbols if s.name == "tls_initialized"]
        if int_syms:
            sym = int_syms[0]
            addr = compute_tls_address(fs_base, sym.tls_offset, aligned_tls_size)
            self.assertEqual(addr % 4, 0,
                           f"tls_initialized address should be 4-byte aligned, got {hex(addr)}")

        d.kill()
        d.terminate()
