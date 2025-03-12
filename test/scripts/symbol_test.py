#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

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