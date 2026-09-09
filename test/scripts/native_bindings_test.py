"""Lifetime and conversion contracts shared by linked and split nanobind builds."""

import gc
import platform
import subprocess
import sys
from pathlib import Path
from unittest import TestCase

from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger
from libdebug.native import libdebug_debug_sym_parser as symbols


class NativeBindingsTest(TestCase):
    def test_symbol_children_keep_storage_alive(self):
        info = symbols.read_elf_info(RESOLVE_EXE("basic_test"), 1)
        vector = info.symbols
        symbol = vector[0]
        expected = (symbol.name, symbol.low_pc, symbol.high_pc)
        iterator = iter(vector)
        del info, vector
        gc.collect()
        self.assertEqual((symbol.name, symbol.low_pc, symbol.high_pc), expected)
        self.assertEqual(next(iterator).name, expected[0])
        del iterator
        gc.collect()
        self.assertEqual(symbol.name, expected[0])

    def test_register_ownership_and_array_conversion(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        try:
            d.run()
            holder = d.threads[0]._register_holder
            regs = holder.register_file
            fpregs = holder.fp_register_file
            field = "pc" if platform.machine() == "aarch64" else (
                "rip" if platform.machine() == "x86_64" else "eip"
            )
            expected = getattr(regs, field)
            setattr(regs, field, expected)
            self.assertEqual(getattr(regs, field), expected)
            # Test setters/getters without writing uninitialized FP state to the tracee.
            if platform.machine() == "aarch64":
                registers = fpregs.vregs
            else:
                registers = fpregs.xmm0
            if registers:
                register = registers[0]
                register.data = list(range(16))
                self.assertEqual(register.data, list(range(16)))
                copy = register.data
                copy[0] = 99
                self.assertEqual(register.data[0], 0)
                self.assertEqual(registers[0].data, list(range(16)))
                with self.assertRaises(TypeError):
                    register.data = [0] * 15
                with self.assertRaises(TypeError):
                    register.data = [256] * 16
            d.kill()
        finally:
            d.terminate()
        del d, holder
        gc.collect()
        self.assertEqual(getattr(regs, field), expected)
        if registers:
            del fpregs, registers
            gc.collect()
            self.assertEqual(register.data, list(range(16)))

    def test_native_shutdown_in_subprocess(self):
        binary = str(Path(RESOLVE_EXE("basic_test")).resolve())
        code = """
import sys
from libdebug import debugger
from libdebug.native import libdebug_debug_sym_parser as symbols
d = debugger(sys.argv[1])
d.run()
regs = d.threads[0]._register_holder.register_file
fpregs = d.threads[0]._register_holder.fp_register_file
info = symbols.read_elf_info(sys.argv[1], 1)
symbol = info.symbols[0]
d.kill()
d.terminate()
"""
        result = subprocess.run([sys.executable, "-c", code, binary], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("nanobind: leaked", result.stderr)
