#!/usr/bin/env python3

"""
Unit test for PLT symbols functionality in libdebug.
This test can be run when the libdebug build is working.
"""

import unittest
import tempfile
import subprocess
import os
from pathlib import Path

class TestPLTSymbols(unittest.TestCase):
    """Test cases for PLT symbols functionality"""
    
    @classmethod
    def setUpClass(cls):
        """Create a test binary with known PLT symbols"""
        test_c = '''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int test_function() {
    printf("Test function\\n");
    char *buffer = malloc(100);
    if (buffer) {
        strcpy(buffer, "test");
        int result = strcmp(buffer, "test");
        free(buffer);
        return result;
    }
    return -1;
}

int main() {
    return test_function();
}
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(test_c)
            cls.source_file = f.name
        
        cls.binary_file = cls.source_file.replace('.c', '')
        subprocess.run(['gcc', '-O0', '-o', cls.binary_file, cls.source_file], check=True)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test files"""
        for file_path in [cls.source_file, cls.binary_file]:
            if os.path.exists(file_path):
                os.unlink(file_path)
    
    def test_plt_symbols_present(self):
        """Test that PLT symbols are present in the symbols list"""
        try:
            import libdebug
        except ImportError:
            self.skipTest("libdebug not available")
        
        d = libdebug.debugger(self.binary_file)
        d.run()
        
        try:
            # Get all symbols
            all_symbols = list(d.symbols)
            
            # Filter PLT symbols
            plt_symbols = [sym for sym in all_symbols if sym.name.startswith('plt@')]
            
            # We should have PLT symbols
            self.assertGreater(len(plt_symbols), 0, "No PLT symbols found")
            
            # Check for expected PLT symbols
            expected_plt_symbols = ['plt@printf', 'plt@malloc', 'plt@free', 'plt@strcmp', 'plt@strcpy']
            found_plt_symbols = [sym.name for sym in plt_symbols]
            
            found_expected = [sym for sym in expected_plt_symbols if sym in found_plt_symbols]
            self.assertGreater(len(found_expected), 2, 
                             f"Expected at least 3 PLT symbols, found: {found_plt_symbols}")
            
        finally:
            d.kill()
            d.terminate()
    
    def test_plt_symbol_access(self):
        """Test that PLT symbols can be accessed by name"""
        try:
            import libdebug
        except ImportError:
            self.skipTest("libdebug not available")
        
        d = libdebug.debugger(self.binary_file)
        d.run()
        
        try:
            # Try to access a PLT symbol by name
            plt_symbols = [sym for sym in d.symbols if sym.name.startswith('plt@')]
            
            if plt_symbols:
                test_symbol = plt_symbols[0]
                
                # Test symbol access by name
                symbol_by_name = d.symbols[test_symbol.name]
                self.assertIsNotNone(symbol_by_name)
                
                # Verify it's the same symbol
                self.assertEqual(symbol_by_name[0].start, test_symbol.start)
                
        finally:
            d.kill()
            d.terminate()
    
    def test_plt_symbol_breakpoint(self):
        """Test that breakpoints can be set on PLT symbols"""
        try:
            import libdebug
        except ImportError:
            self.skipTest("libdebug not available")
        
        d = libdebug.debugger(self.binary_file)
        d.run()
        
        try:
            # Find a PLT symbol
            plt_symbols = [sym for sym in d.symbols if sym.name.startswith('plt@')]
            
            if plt_symbols:
                test_symbol = plt_symbols[0]
                
                # Try to set a breakpoint
                try:
                    bp = d.breakpoint(test_symbol.name)
                    self.assertIsNotNone(bp)
                    
                    # Verify breakpoint address
                    self.assertEqual(bp.address, test_symbol.start)
                    
                    # Clean up
                    bp.disable()
                    
                except Exception as e:
                    self.fail(f"Failed to set breakpoint on PLT symbol {test_symbol.name}: {e}")
                    
        finally:
            d.kill()
            d.terminate()
    
    def test_plt_symbol_properties(self):
        """Test that PLT symbols have correct properties"""
        try:
            import libdebug
        except ImportError:
            self.skipTest("libdebug not available")
        
        d = libdebug.debugger(self.binary_file)
        d.run()
        
        try:
            plt_symbols = [sym for sym in d.symbols if sym.name.startswith('plt@')]
            
            for sym in plt_symbols:
                # PLT symbols should have valid addresses
                self.assertGreater(sym.start, 0)
                self.assertGreater(sym.end, sym.start)
                
                # PLT symbol names should start with 'plt@'
                self.assertTrue(sym.name.startswith('plt@'))
                
                # PLT symbols should be marked as external
                self.assertTrue(sym.is_external)
                
        finally:
            d.kill()
            d.terminate()

if __name__ == '__main__':
    # Check if we can create the test binary first
    try:
        subprocess.run(['gcc', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("GCC not available - skipping tests")
        exit(0)
    
    unittest.main()