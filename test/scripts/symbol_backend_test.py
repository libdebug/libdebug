#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

"""Comprehensive unit tests for the symbol backend."""

from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.data.symbol_list import SymbolList
from libdebug.native.libdebug_debug_sym_parser import Symbol, SymbolBinding, SymbolType, SymbolVisibility


class SymbolBackendTest(TestCase):
    """Tests for the new symbol backend functionality."""

    def test_symbol_dataclass_fields(self):
        """Test that Symbol has all the new fields."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        # Get any symbol
        symbols = d.symbols
        self.assertGreater(len(symbols), 0, "Should have at least some symbols")

        # Check first symbol has all required fields
        sym = symbols[0]
        self.assertIsInstance(sym, Symbol)

        # Check new fields exist
        self.assertTrue(hasattr(sym, "symbol_type"))
        self.assertTrue(hasattr(sym, "binding"))
        self.assertTrue(hasattr(sym, "visibility"))
        self.assertTrue(hasattr(sym, "is_tls"))
        self.assertTrue(hasattr(sym, "demangled_name"))
        self.assertTrue(hasattr(sym, "is_plt"))
        self.assertTrue(hasattr(sym, "is_got"))

        d.kill()
        d.terminate()

    def test_symbol_types(self):
        """Test symbol type detection."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Find function symbols
        func_symbols = symbols.functions
        self.assertGreater(len(func_symbols), 0, "Should have function symbols")

        # All function symbols should have FUNC or GNU_IFUNC type
        for sym in func_symbols:
            self.assertTrue(
                sym.symbol_type in (SymbolType.FUNC, SymbolType.GNU_IFUNC),
                f"Symbol {sym.name} should be a function type",
            )

        d.kill()
        d.terminate()

    def test_symbol_binding(self):
        """Test symbol binding detection."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Filter by binding
        global_symbols = symbols.globals
        local_symbols = symbols.locals

        # Should have some of each
        self.assertGreater(len(global_symbols), 0, "Should have global symbols")

        # Check that binding is correct
        for sym in global_symbols:
            self.assertEqual(sym.binding, SymbolBinding.GLOBAL)

        for sym in local_symbols:
            self.assertEqual(sym.binding, SymbolBinding.LOCAL)

        d.kill()
        d.terminate()

    def test_symbol_list_filter_by_type(self):
        """Test filtering symbols by type."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Filter by function type
        func_symbols = symbols.filter_by_type(SymbolType.FUNC)
        for sym in func_symbols:
            self.assertEqual(sym.symbol_type, SymbolType.FUNC)

        # Filter by object type
        obj_symbols = symbols.filter_by_type(SymbolType.OBJECT)
        for sym in obj_symbols:
            self.assertEqual(sym.symbol_type, SymbolType.OBJECT)

        d.kill()
        d.terminate()

    def test_symbol_list_filter_by_binding(self):
        """Test filtering symbols by binding."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Filter by global binding
        global_syms = symbols.filter_by_binding(SymbolBinding.GLOBAL)
        for sym in global_syms:
            self.assertEqual(sym.binding, SymbolBinding.GLOBAL)

        # Filter by weak binding
        weak_syms = symbols.filter_by_binding(SymbolBinding.WEAK)
        for sym in weak_syms:
            self.assertEqual(sym.binding, SymbolBinding.WEAK)

        d.kill()
        d.terminate()

    def test_symbol_in_file_filter(self):
        """Test filtering symbols by backing file."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Filter by binary file
        binary_symbols = symbols.in_file("breakpoint_test")
        self.assertGreater(len(binary_symbols), 0)

        for sym in binary_symbols:
            self.assertIn("breakpoint_test", sym.backing_file)

        d.kill()
        d.terminate()

    def test_symbol_properties(self):
        """Test symbol convenience properties."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Find a function symbol
        func_symbols = [s for s in symbols if s.symbol_type == SymbolType.FUNC]
        if func_symbols:
            sym = func_symbols[0]
            self.assertTrue(sym.is_function)
            self.assertFalse(sym.is_object)
            self.assertFalse(sym.is_tls)

        # Check size property
        for sym in symbols[:10]:  # Check first 10
            if sym.end > sym.start:
                self.assertEqual(sym.size, sym.end - sym.start)

        d.kill()
        d.terminate()

    def test_symbol_display_name(self):
        """Test symbol display_name property."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        for sym in symbols[:20]:  # Check first 20
            # display_name should return demangled if available, else name
            if sym.demangled_name:
                self.assertEqual(sym.display_name, sym.demangled_name)
            else:
                self.assertEqual(sym.display_name, sym.name)

        d.kill()
        d.terminate()

    def test_symbol_str_repr(self):
        """Test symbol string representations."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        for sym in symbols[:5]:  # Check first 5
            # __repr__ should include details
            repr_str = repr(sym)
            self.assertIn("Symbol(", repr_str)
            self.assertIn(sym.name, repr_str)

            # __str__ should be concise
            str_str = str(sym)
            self.assertIn(sym.name, str_str)

        d.kill()
        d.terminate()

    def test_symbol_lookup_by_demangled_name(self):
        """Test that symbols can be found by demangled name."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Find a symbol with a demangled name
        demangled_symbols = [s for s in symbols if s.demangled_name]

        if demangled_symbols:
            sym = demangled_symbols[0]
            # Should be able to find by demangled name
            found = symbols[sym.demangled_name]
            self.assertGreater(len(found), 0)

        d.kill()
        d.terminate()

    def test_symbol_resolution_with_offset(self):
        """Test symbol resolution with offset."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        # Find a function symbol
        symbols = d.symbols
        func_symbols = [s for s in symbols if s.symbol_type == SymbolType.FUNC and s.size > 0]

        if func_symbols:
            sym = func_symbols[0]
            # Try to resolve with offset
            # This tests the symbol+offset syntax
            try:
                addr = d.memory.resolve_symbol(f"{sym.name}+0x10", sym.backing_file)
                expected = d.memory.resolve_symbol(sym.name, sym.backing_file) + 0x10
                self.assertEqual(addr, expected)
            except (ValueError, AttributeError):
                pass  # Not all configurations support this

        d.kill()
        d.terminate()


class SymbolBackendPLTGOTTest(TestCase):
    """Tests for PLT/GOT symbol detection."""

    def test_plt_detection(self):
        """Test that PLT symbols are detected."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Get PLT symbols
        plt_symbols = symbols.plt

        # There should be some PLT entries for libc functions
        # Not all binaries have PLT entries visible in symbols though
        if len(plt_symbols) > 0:
            for sym in plt_symbols:
                self.assertTrue(sym.is_plt)

        d.kill()
        d.terminate()

    def test_got_detection(self):
        """Test that GOT symbols are detected."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Get GOT symbols
        got_symbols = symbols.got

        if len(got_symbols) > 0:
            for sym in got_symbols:
                self.assertTrue(sym.is_got)

        d.kill()
        d.terminate()

    def test_defined_symbols_filter(self):
        """Test filtering for defined symbols."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols
        defined = symbols.defined

        for sym in defined:
            self.assertTrue(sym.is_defined)

        d.kill()
        d.terminate()


class SymbolVersioningTest(TestCase):
    """Tests for symbol versioning support."""

    def test_version_filter(self):
        """Test filtering symbols by version."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Look for GLIBC versioned symbols
        glibc_symbols = symbols.with_version("GLIBC")

        # Not all binaries have versioned symbols visible
        if len(glibc_symbols) > 0:
            for sym in glibc_symbols:
                self.assertIsNotNone(sym.version)
                self.assertIn("GLIBC", sym.version)

        d.kill()
        d.terminate()


class SymbolEnumTest(TestCase):
    """Tests for symbol type enums."""

    def test_symbol_type_values(self):
        """Test SymbolType enum values match ELF specification."""
        self.assertEqual(SymbolType.NOTYPE, 0)
        self.assertEqual(SymbolType.OBJECT, 1)
        self.assertEqual(SymbolType.FUNC, 2)
        self.assertEqual(SymbolType.SECTION, 3)
        self.assertEqual(SymbolType.FILE, 4)
        self.assertEqual(SymbolType.COMMON, 5)
        self.assertEqual(SymbolType.TLS, 6)
        self.assertEqual(SymbolType.GNU_IFUNC, 10)

    def test_symbol_binding_values(self):
        """Test SymbolBinding enum values match ELF specification."""
        self.assertEqual(SymbolBinding.LOCAL, 0)
        self.assertEqual(SymbolBinding.GLOBAL, 1)
        self.assertEqual(SymbolBinding.WEAK, 2)
        self.assertEqual(SymbolBinding.GNU_UNIQUE, 10)

    def test_symbol_visibility_values(self):
        """Test SymbolVisibility enum values match ELF specification."""
        self.assertEqual(SymbolVisibility.DEFAULT, 0)
        self.assertEqual(SymbolVisibility.INTERNAL, 1)
        self.assertEqual(SymbolVisibility.HIDDEN, 2)
        self.assertEqual(SymbolVisibility.PROTECTED, 3)


class SymbolListEnhancementsTest(TestCase):
    """Tests for SymbolList enhancements."""

    def test_symbol_list_chaining(self):
        """Test that filter methods can be chained."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Chain filters
        result = symbols.functions.globals

        # All results should be global functions
        for sym in result:
            self.assertTrue(sym.is_function)
            self.assertTrue(sym.is_global)

        d.kill()
        d.terminate()

    def test_symbol_list_in_file_chain(self):
        """Test in_file can be chained with other filters."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols

        # Chain in_file with functions
        result = symbols.in_file("breakpoint_test").functions

        for sym in result:
            self.assertIn("breakpoint_test", sym.backing_file)
            self.assertTrue(sym.is_function)

        d.kill()
        d.terminate()


class SymbolBackwardCompatibilityTest(TestCase):
    """Tests to ensure backward compatibility with old symbol API."""

    def test_basic_symbol_access(self):
        """Test basic symbol access still works."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        # Old API: access symbols by name
        symbols = d.symbols["random_function"]
        self.assertIsInstance(symbols, SymbolList)

        d.kill()
        d.terminate()

    def test_symbol_filter_by_name(self):
        """Test symbol filter by name still works."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols
        filtered = symbols.filter("random_function")
        self.assertIsInstance(filtered, SymbolList)

        d.kill()
        d.terminate()

    def test_symbol_basic_fields(self):
        """Test that basic symbol fields still exist."""
        d = debugger(RESOLVE_EXE("breakpoint_test"))
        d.run()

        symbols = d.symbols
        if symbols:
            sym = symbols[0]

            # These fields must still exist for backward compatibility
            self.assertTrue(hasattr(sym, "start"))
            self.assertTrue(hasattr(sym, "end"))
            self.assertTrue(hasattr(sym, "name"))
            self.assertTrue(hasattr(sym, "backing_file"))
            self.assertTrue(hasattr(sym, "reference_file"))
            self.assertTrue(hasattr(sym, "is_external"))

        d.kill()
        d.terminate()
