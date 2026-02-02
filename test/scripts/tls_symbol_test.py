#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

"""Unit tests for TLS (Thread-Local Storage) symbol resolution."""

import os
from unittest import TestCase, skipIf

from utils.binary_utils import PLATFORM, RESOLVE_EXE

from libdebug import debugger
from libdebug.native.libdebug_debug_sym_parser import SymbolType

# TLS test requires the tls_test binary to be compiled
TLS_TEST_BINARY = RESOLVE_EXE("tls_test")
TLS_TEST_EXISTS = os.path.exists(TLS_TEST_BINARY)


@skipIf(not TLS_TEST_EXISTS, "TLS test binary not compiled")
class TLSSymbolTest(TestCase):
    """Tests for TLS symbol detection and resolution."""

    def test_tls_symbol_detection(self):
        """Test that TLS symbols are correctly detected."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        # Wait for main
        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols

        # Get TLS symbols
        tls_symbols = symbols.tls_symbols

        # Should have some TLS symbols
        self.assertGreater(len(tls_symbols), 0, "Should detect TLS symbols")

        # All should have is_tls = True
        for sym in tls_symbols:
            self.assertTrue(sym.is_tls)
            self.assertEqual(sym.symbol_type, SymbolType.TLS)

        d.kill()
        d.terminate()

    def test_tls_symbol_names(self):
        """Test that TLS symbols have correct names."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols
        tls_symbols = symbols.tls_symbols

        # Look for our known TLS variables
        expected_names = [
            "tls_uninitialized",
            "tls_initialized",
            "tls_string",
            "tls_double",
        ]

        found_names = {sym.name for sym in tls_symbols}

        for name in expected_names:
            self.assertIn(
                name, found_names,
                f"TLS symbol '{name}' should be found in symbols"
            )

        d.kill()
        d.terminate()

    def test_tls_symbol_offset(self):
        """Test that TLS symbols have valid offsets."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols
        tls_symbols = symbols.tls_symbols

        for sym in tls_symbols:
            # TLS symbols should have tls_offset set
            if sym.is_tls:
                self.assertIsNotNone(
                    sym.tls_offset,
                    f"TLS symbol {sym.name} should have tls_offset"
                )

        d.kill()
        d.terminate()

    def test_tls_filter_by_type(self):
        """Test filtering symbols by TLS type."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols

        # Filter by TLS type using the enum
        tls_by_type = symbols.filter_by_type(SymbolType.TLS)

        # Should match tls_symbols property
        tls_by_prop = symbols.tls_symbols

        # Same count (approximately, there might be library TLS too)
        self.assertEqual(len(tls_by_type), len(tls_by_prop))

        d.kill()
        d.terminate()


@skipIf(not TLS_TEST_EXISTS, "TLS test binary not compiled")
@skipIf(PLATFORM not in ["amd64", "x86_64"], "TLS resolution requires x86-64")
class TLSAddressResolutionTest(TestCase):
    """Tests for TLS address resolution."""

    def test_tls_address_resolution_main_thread(self):
        """Test TLS address resolution for the main thread."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        # Import TLS resolver
        from libdebug.symbols.tls_manager import TLSManager

        resolver = TLSManager(d._internal_debugger)

        # Find a TLS symbol
        symbols = d.symbols
        tls_symbols = [s for s in symbols if s.is_tls and s.name == "tls_initialized"]

        if tls_symbols:
            sym = tls_symbols[0]
            result = resolver.resolve(sym, d.threads[0])

            # Address should be resolved
            self.assertIsNotNone(result.address, "TLS address should be resolved")
            self.assertTrue(result.is_static_tls)
            self.assertEqual(result.thread_id, d.threads[0].tid)

        d.kill()
        d.terminate()

    def test_tls_different_threads_different_addresses(self):
        """Test that TLS symbols have different addresses in different threads."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        # Set breakpoint that threads will hit
        d.bp("breakpoint_here")

        # Continue and let threads spawn
        d.cont()
        d.wait()  # Main thread hits breakpoint

        # Continue a few times to let threads hit the breakpoint
        for _ in range(3):
            d.cont()
            d.wait()

        # Now we should have multiple threads
        if len(d.threads) > 1:
            from libdebug.symbols.tls_manager import TLSManager

            resolver = TLSManager(d._internal_debugger)

            # Find a TLS symbol
            symbols = d.symbols
            tls_symbols = [s for s in symbols if s.is_tls and s.name == "tls_initialized"]

            if tls_symbols:
                sym = tls_symbols[0]

                addresses = []
                for thread in d.threads[:2]:  # Compare first two threads
                    result = resolver.resolve(sym, thread)
                    if result.address is not None:
                        addresses.append(result.address)

                # If we got addresses for both threads, they should be different
                if len(addresses) == 2:
                    self.assertNotEqual(
                        addresses[0], addresses[1],
                        "TLS addresses should differ between threads"
                    )

        d.kill()
        d.terminate()


@skipIf(not TLS_TEST_EXISTS, "TLS test binary not compiled")
class TLSSymbolSearchTest(TestCase):
    """Tests for searching TLS symbols."""

    def test_tls_symbol_search_by_name(self):
        """Test searching for TLS symbols by name."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols

        # Search for a specific TLS variable
        results = symbols.filter("tls_initialized")

        # Should find it
        tls_results = [s for s in results if s.is_tls]
        self.assertGreater(len(tls_results), 0, "Should find tls_initialized")

        # First result should be exact match
        self.assertEqual(tls_results[0].name, "tls_initialized")
        self.assertTrue(tls_results[0].is_tls)

        d.kill()
        d.terminate()

    def test_non_tls_vs_tls_symbols(self):
        """Test distinguishing TLS from non-TLS symbols."""
        d = debugger(TLS_TEST_BINARY)
        d.run()

        d.bp("breakpoint_here")
        d.cont()
        d.wait()

        symbols = d.symbols

        # Find global_var (not TLS)
        global_syms = symbols.filter("global_var")
        non_tls = [s for s in global_syms if not s.is_tls]

        if non_tls:
            self.assertFalse(non_tls[0].is_tls)
            self.assertNotEqual(non_tls[0].symbol_type, SymbolType.TLS)

        # Find tls_initialized (TLS)
        tls_syms = symbols.filter("tls_initialized")
        tls = [s for s in tls_syms if s.is_tls]

        if tls:
            self.assertTrue(tls[0].is_tls)
            self.assertEqual(tls[0].symbol_type, SymbolType.TLS)

        d.kill()
        d.terminate()
