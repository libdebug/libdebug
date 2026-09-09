#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import struct
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile
from libdebug.native.libdebug_debug_sym_parser import read_elf_info

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE, PLATFORM

from libdebug.data.symbol_list import SymbolList
from libdebug.data.symbol import Symbol

from libdebug import debugger

class SymbolTest(TestCase):
    def test_plt_relocation_targets(self):
        expected = {
            "amd64": {"puts@plt": 0x401040, "printf@plt": 0x401050},
            "i386": {"__libc_start_main@plt": 0x8049030, "printf@plt": 0x8049050, "puts@plt": 0x8049060},
        }
        for arch, addresses in expected.items():
            for reordered in (False, True):
                with self.subTest(arch=arch, reordered=reordered):
                    contents = bytearray(Path(f"binaries/{arch}/plt_ifunc").read_bytes())
                    elf = ELFFile(io.BytesIO(contents))
                    rel = elf.get_section_by_name(".rela.plt" if arch == "amd64" else ".rel.plt")
                    got = {elf.get_section(rel["sh_link"]).get_symbol(r["r_info_sym"]).name + "@got.plt": r["r_offset"]
                           for r in rel.iter_relocations() if r["r_info_sym"]}
                    if reordered:
                        start, size, entry = rel["sh_offset"], rel["sh_size"], rel["sh_entsize"]
                        records = [contents[i:i + entry] for i in range(start, start + size, entry)]
                        contents[start:start + size] = b"".join(reversed(records))
                    with tempfile.NamedTemporaryFile() as target:
                        target.write(contents)
                        target.flush()
                        symbols = read_elf_info(target.name, 1).symbols
                    self.assertEqual({s.name: s.low_pc for s in symbols if s.name.endswith("@plt")}, addresses)
                    slots = [s for s in symbols if s.name.endswith("@got.plt")]
                    self.assertEqual({s.name: s.low_pc for s in slots}, got)
                    self.assertTrue(all(s.high_pc - s.low_pc == (8 if arch == "amd64" else 4) for s in slots))
                    self.assertEqual(len([s for s in symbols if s.name.endswith("@plt")]), len(addresses))

    @skipUnless(PLATFORM in ("amd64", "i386"), "Requires x86")
    def test_plt_ifunc_breakpoints(self):
        d = debugger(RESOLVE_EXE("plt_ifunc"))
        try:
            pipe = d.run()
            puts = d.bp("puts@plt", callback=lambda *_: None)
            printf = d.bp("printf@plt", callback=lambda *_: None)
            d.cont()
            self.assertEqual(pipe.recvline(), b"before ifunc")
            self.assertEqual(pipe.recvline(), b"after ifunc: 42")
            d.wait()
            self.assertEqual(puts.hit_count, 1)
            self.assertEqual(printf.hit_count, 1)
        finally:
            d.kill()
            d.terminate()

    def test_plt_unknown_and_bnd_stubs(self):
        for arch in ("amd64", "i386"):
            for form in ("unknown", "bnd"):
                with self.subTest(arch=arch, form=form):
                    contents = bytearray(Path(f"binaries/{arch}/basic_test").read_bytes())
                    elf = ELFFile(io.BytesIO(contents))
                    plt = elf.get_section_by_name(".plt")
                    offset = plt["sh_offset"] + 16
                    address = plt["sh_addr"] + 16
                    name = "puts@plt" if arch == "amd64" else "__libc_start_main@plt"
                    if form == "unknown":
                        contents[offset:offset + 6] = b"\x90" * 6
                    else:
                        jump = bytes(contents[offset:offset + 6])
                        operand = struct.unpack("<I", jump[2:])[0]
                        if arch == "amd64":
                            operand = (operand - 1) & 0xffffffff
                        contents[offset:offset + 7] = b"\xf2" + jump[:2] + struct.pack("<I", operand)
                    with tempfile.NamedTemporaryFile() as target:
                        target.write(contents)
                        target.flush()
                        symbols = read_elf_info(target.name, 1).symbols
                    matches = [s.low_pc for s in symbols if s.name == name]
                    self.assertEqual(matches, [] if form == "unknown" else [address])

    def test_ordinary_aarch64_plt(self):
        symbols = read_elf_info("binaries/aarch64/telescope_test", 1).symbols
        expected = {"__libc_start_main@plt": 0x720, "__cxa_finalize@plt": 0x730,
                    "__stack_chk_fail@plt": 0x740, "__gmon_start__@plt": 0x750,
                    "abort@plt": 0x760, "puts@plt": 0x770,
                    "getchar@plt": 0x780, "printf@plt": 0x790}
        self.assertEqual({s.name: s.low_pc for s in symbols if s.name.endswith("@plt")}, expected)

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
