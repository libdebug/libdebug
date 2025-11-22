#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE, PLATFORM

from libdebug.data.symbol_list import SymbolList
from libdebug.data.symbol import Symbol

from libdebug import debugger

class SymbolTest(TestCase):
    def test_symbol_access(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        self.assertIsInstance(d.symbols["random_function"], SymbolList)
        self.assertIsInstance(d.symbols[0], Symbol)
        self.assertIsInstance(d.symbols.filter("random_function"), SymbolList)

        d.kill()
        d.terminate()
        
    def test_symbols_access_slices(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()
        
        # Test the __getitem__ method
        d.symbols["random_function"][0]
        d.symbols["random_function"][:1]
        d.symbols["random_function"][1:]
        d.symbols["random_function"][0:1]
        d.symbols["random_function"][:]
        d.symbols["random_function"][-1]

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_plt_symbols_pie1(self):
        d = debugger(RESOLVE_EXE("telescope_test"))

        d.run()

        symbols = d.symbols

        libc_start_main_plt = symbols.filter("__libc_start_main@plt")
        printf_plt = symbols.filter("printf@plt")
        getchar_plt = symbols.filter("getchar@plt")
        stack_chk_fail_plt = symbols.filter("__stack_chk_fail@plt")
        puts_plt = symbols.filter("puts@plt")

        self.assertEqual(len(libc_start_main_plt), 1)
        self.assertEqual(len(printf_plt), 1)
        self.assertEqual(len(getchar_plt), 1)
        self.assertEqual(len(stack_chk_fail_plt), 1)
        self.assertEqual(len(puts_plt), 1)

        # Check the offset of the symbols
        self.assertEqual(libc_start_main_plt[0].start, 0x1040)
        self.assertEqual(printf_plt[0].start, 0x1050)
        self.assertEqual(getchar_plt[0].start, 0x1060)
        self.assertEqual(stack_chk_fail_plt[0].start, 0x1070)
        self.assertEqual(puts_plt[0].start, 0x1080)

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "__libc_start_main@plt",
            "printf@plt",
            "getchar@plt",
            "__stack_chk_fail@plt",
            "puts@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_plt_symbols_pie2(self):
        d = debugger(RESOLVE_EXE("telescope_test"))

        d.run()

        symbols = d.symbols

        puts_plt = symbols.filter("puts@plt")
        stack_chk_fail_plt = symbols.filter("__stack_chk_fail@plt")
        printf_plt = symbols.filter("printf@plt")
        getchar_plt = symbols.filter("getchar@plt")

        self.assertEqual(len(puts_plt), 1)
        self.assertEqual(len(stack_chk_fail_plt), 1)
        self.assertEqual(len(printf_plt), 1)
        self.assertEqual(len(getchar_plt), 1)

        # Check the offset of the symbols
        self.assertEqual(puts_plt[0].start, 0x1080)
        self.assertEqual(stack_chk_fail_plt[0].start, 0x1090)
        self.assertEqual(printf_plt[0].start, 0x10a0)
        self.assertEqual(getchar_plt[0].start, 0x10b0)

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "puts@plt",
            "__stack_chk_fail@plt",
            "printf@plt",
            "getchar@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_plt_symbols_no_pie1(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        symbols = d.symbols

        libc_start_main_plt = symbols.filter("__libc_start_main@plt")
        puts_plt = symbols.filter("puts@plt")

        self.assertEqual(len(libc_start_main_plt), 1)
        self.assertEqual(len(puts_plt), 1)

        # Check the address of the symbols
        self.assertEqual(libc_start_main_plt[0].start, 0x8049030)
        self.assertEqual(puts_plt[0].start, 0x8049040)

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "__libc_start_main@plt",
            "puts@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_plt_symbols_no_pie2(self):
        d = debugger(RESOLVE_EXE("basic_test"))

        d.run()

        symbols = d.symbols

        puts_plt = symbols.filter("puts@plt")

        self.assertEqual(len(puts_plt), 1)

        # Check the address of the symbols
        self.assertEqual(puts_plt[0].start, 0x401030)

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "puts@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i386")
    def test_plt_symbols_no_pie3(self):
        d = debugger(RESOLVE_EXE("backtrace_test"))

        d.run()

        symbols = d.symbols

        libc_start_main_plt = symbols.filter("__libc_start_main@plt")
        printf_plt = symbols.filter("printf@plt")

        self.assertEqual(len(libc_start_main_plt), 1)
        self.assertEqual(len(printf_plt), 1)

        # Check the address of the symbols
        self.assertEqual(libc_start_main_plt[0].start, 0x8049030)
        self.assertEqual(printf_plt[0].start, 0x8049040)        

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "__libc_start_main@plt",
            "printf@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_plt_symbols_no_pie4(self):
        d = debugger(RESOLVE_EXE("breakpoint_test"))

        d.run()

        symbols = d.symbols

        puts_plt = symbols.filter("puts@plt")
        printf_plt = symbols.filter("printf@plt")

        self.assertEqual(len(puts_plt), 1)
        self.assertEqual(len(printf_plt), 1)

        # Check the address of the symbols
        self.assertEqual(puts_plt[0].start, 0x401030)
        self.assertEqual(printf_plt[0].start, 0x401040)

        # No other plt symbols should be present
        other_plt_symbols = [s for s in symbols if s.name.endswith("@plt") and s.name not in [
            "puts@plt",
            "printf@plt"
        ] and s.backing_file == d.path]
        self.assertEqual(len(other_plt_symbols), 0)

        d.kill()
        d.terminate()
