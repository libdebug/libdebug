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
from libdebug.ptrace.native.libdebug_ptrace_binding import LibdebugPtraceInterface, PtraceFPRegsStructDefinition
from libdebug.ptrace.ptrace_native_interface_provider import get_ptrace_fpregs_definition


class NativeBindingsTest(TestCase):
    def test_legacy_x87_bank_bounds(self):
        if platform.machine() == "aarch64":
            self.skipTest("Requires x86 register layout")
        d = debugger(RESOLVE_EXE("basic_test"))
        try:
            d.run()
            definition = PtraceFPRegsStructDefinition(
                struct_size=108, avx_ymm0_offset=0, avx512_zmm0_offset=0,
                avx512_zmm1_offset=0, type=0, has_xsave=False,
            )
            interface = LibdebugPtraceInterface(definition)
            _, fpregs = interface.register_thread(d.tid)
            self.assertEqual(len(fpregs.legacy_st_space), 8)
            fpregs.set_legacy_st_space(7, bytes(range(10)))
            self.assertEqual(fpregs.get_legacy_st_space(7), bytes(range(10)))
            with self.assertRaises(IndexError):
                fpregs.get_legacy_st_space(8)
            with self.assertRaises(IndexError):
                fpregs.set_legacy_st_space(8, bytes(10))
            interface.cleanup()
            d.kill()
        finally:
            d.terminate()

    def test_indexed_fp_bytes(self):
        d = debugger(RESOLVE_EXE("basic_test"))
        snapshots = []
        try:
            d.run()
            fpregs = d.threads[0]._register_holder.fp_register_file
            if platform.machine() == "aarch64":
                banks = ["vregs"]
            else:
                banks = ["mmx", "xmm0"] if fpregs.has_xsave else ["legacy_st_space"]
                definition = get_ptrace_fpregs_definition()
                for bank, offset in (
                    ("ymm0", definition.avx_ymm0_offset),
                    ("zmm0", definition.avx512_zmm0_offset),
                    ("zmm1", definition.avx512_zmm1_offset),
                ):
                    if offset:
                        banks.append(bank)
            for bank in banks:
                with self.subTest(bank=bank):
                    registers = getattr(fpregs, bank)
                    get = getattr(fpregs, f"get_{bank}")
                    put = getattr(fpregs, f"set_{bank}")
                    width = len(registers[0].data)
                    value = bytes(range(width))
                    for index in (0, len(registers) - 1):
                        put(index, value)
                        snapshot = get(index)
                        self.assertIs(type(snapshot), bytes)
                        self.assertEqual(snapshot, value)
                        self.assertEqual(registers[index].data, list(value))
                        registers[index].data = [255] * width
                        self.assertEqual(get(index), b"\xff" * width)
                        self.assertEqual(snapshot, value)
                        snapshots.append((snapshot, value))
                    for index in (-1, len(registers)):
                        with self.assertRaises((TypeError, IndexError)):
                            get(index)
                        with self.assertRaises((TypeError, IndexError)):
                            put(index, value)
                    for bad_value in (value[:-1], value + b"\x00"):
                        with self.assertRaises(ValueError):
                            put(0, bad_value)
                        self.assertEqual(get(0), b"\xff" * width)
                    with self.assertRaises(TypeError):
                        get(0.0)
                    for bad_value in (list(value), bytearray(value), None):
                        with self.assertRaises(TypeError):
                            put(0, bad_value)
            # Do not flush the deliberately modified FP state to the tracee.
            d.kill()
        finally:
            d.terminate()
        del d, fpregs, registers, get, put
        gc.collect()
        for snapshot, value in snapshots:
            self.assertEqual(snapshot, value)

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
