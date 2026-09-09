#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import logging
import json
import subprocess
import struct
import sys
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.construct import Container
from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE, PLATFORM

from libdebug import debugger


class CorruptedELFTest(TestCase):
    def _parse_mutated(self, arch, mutate):
        source = Path(f"binaries/{arch}/telescope_test")
        contents = bytearray(source.read_bytes())
        elf = ELFFile(io.BytesIO(contents))
        mutate(elf, contents)
        with tempfile.NamedTemporaryFile() as target:
            target.write(contents)
            target.flush()
            result = subprocess.run(
                [sys.executable, "-c",
                 "import json, sys; from libdebug.native.libdebug_debug_sym_parser import read_elf_info; "
                 "print(json.dumps([(s.name, s.low_pc, s.high_pc) for s in read_elf_info(sys.argv[1], 1).symbols]))",
                 target.name], capture_output=True, text=True, timeout=20,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        symbols = json.loads(result.stdout)
        self.assertTrue(any(name == "main" for name, _, _ in symbols))
        synthetic = [tuple(s) for s in symbols if "@plt" in s[0] or "@got" in s[0]]
        self.assertEqual(len(synthetic), len(set(synthetic)))
        return symbols

    @staticmethod
    def _patch_section(elf, contents, section, **changes):
        index = next(i for i, s in enumerate(elf.iter_sections()) if s.name == section.name)
        header = Container(**dict(section.header))
        header.update(changes)
        offset = elf["e_shoff"] + index * elf["e_shentsize"]
        contents[offset:offset + elf["e_shentsize"]] = elf.structs.Elf_Shdr.build(header)

    def test_invalid_plt_metadata(self):
        for arch in ("amd64", "i386"):
            for fault in ("zero", "small", "large", "partial", "outside", "link", "wrong_link",
                          "sym_size", "sym_link", "str_type"):
                with self.subTest(arch=arch, fault=fault):
                    def mutate(elf, contents):
                        rel = elf.get_section_by_name(".rela.plt" if arch == "amd64" else ".rel.plt")
                        sym = elf.get_section(rel["sh_link"])
                        changes = {
                            "zero": {"sh_entsize": 0}, "small": {"sh_entsize": 1},
                            "large": {"sh_entsize": rel["sh_entsize"] * 2},
                            "partial": {"sh_size": rel["sh_size"] - 1},
                            "outside": {"sh_offset": len(contents) - 1},
                            "link": {"sh_link": elf.num_sections() + 1},
                            "wrong_link": {"sh_link": elf.get_section_index(".text")},
                        }
                        if fault in changes:
                            self._patch_section(elf, contents, rel, **changes[fault])
                        elif fault == "sym_size":
                            self._patch_section(elf, contents, sym, sh_entsize=0)
                        elif fault == "sym_link":
                            self._patch_section(elf, contents, sym, sh_link=elf.num_sections() + 1)
                        else:
                            self._patch_section(elf, contents, elf.get_section(sym["sh_link"]), sh_type="SHT_PROGBITS")
                    symbols = self._parse_mutated(arch, mutate)
                    self.assertFalse(any(name.endswith("@got.plt") for name, _, _ in symbols))

    def test_invalid_plt_records(self):
        for arch in ("amd64", "i386"):
            for fault in ("index", "name", "unterminated"):
                with self.subTest(arch=arch, fault=fault):
                    expected = {}
                    def mutate(elf, contents):
                        rel = elf.get_section_by_name(".rela.plt" if arch == "amd64" else ".rel.plt")
                        sym = elf.get_section(rel["sh_link"])
                        records = list(rel.iter_relocations())
                        for i, record in enumerate(records):
                            if i != 1:
                                expected[sym.get_symbol(record["r_info_sym"]).name + "@got.plt"] = record["r_offset"]
                        bad = records[1]
                        if fault == "index":
                            width = 8 if arch == "amd64" else 4
                            info = (0xffffffff << 32 | 7) if width == 8 else (0xffffff << 8 | 7)
                            struct.pack_into("<Q" if width == 8 else "<I", contents,
                                             rel["sh_offset"] + rel["sh_entsize"] + width, info)
                        else:
                            strings = elf.get_section(sym["sh_link"])
                            name = strings["sh_size"] + 10
                            if fault == "unterminated":
                                name = strings["sh_size"] - 1
                                contents[strings["sh_offset"] + name] = ord("X")
                            struct.pack_into("<I", contents,
                                             sym["sh_offset"] + bad["r_info_sym"] * sym["sh_entsize"], name)
                    symbols = self._parse_mutated(arch, mutate)
                    self.assertEqual({name: lo for name, lo, _ in symbols if name.endswith("@got.plt")}, expected)

    def setUp(self):
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
        self.logger.removeHandler(self.log_handler)
        self.logger.handlers = self.original_handlers
        self.log_handler.close()

    def test_basic_corrupted_elf(self):
        d = debugger(RESOLVE_EXE("corrupted_elf_test"))

        r = d.run()

        # We hijack SIGBUS to SIGCONT to avoid the process to terminate
        hijacker = d.hijack_signal("SIGBUS", "SIGCONT")

        hit = False

        def on_enter_1337(_, __):
            nonlocal hit
            hit = True

        # We check that we can still handle syscalls
        handler = d.handle_syscall(0x1337, on_enter=on_enter_1337)

        d.cont()

        # We ensure that pipes work
        self.assertEqual(r.recvline(), b"Provola!")

        r.sendline(b"3")

        d.kill()
        d.terminate()

        self.assertTrue(hit)
        self.assertEqual(hijacker.hit_count, 1)
        self.assertEqual(handler.hit_count, 1)

        # Validate that we triggered a few warnings
        capture = self.log_capture_string.getvalue()
        self.assertIn("Failed to get the architecture of the binary:", capture)
        self.assertIn("Failed to get the entry point for the given binary:", capture)

    def test_symbol_access_corrupted_elf(self):
        d = debugger(RESOLVE_EXE("corrupted_elf_test"))
        d.run()

        with self.assertRaises(ValueError):
            # This should raise an exception, because the symbol is in the corrupted executable
            d.bp("skill_issue")

        # This should not raise an exception, it just won't contain any symbol from the executable
        d.symbols

        d.kill()
        d.terminate()

        # Validate that we triggered a few warnings
        capture = self.log_capture_string.getvalue()
        self.assertIn("Failed to get the architecture of the binary:", capture)
        self.assertIn("Failed to get the entry point for the given binary:", capture)

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_technically_correct(self):
        #
        # Challenge taken from LACTF 2024
        #
        # Our solution does not involve dynamic analysis
        # The handout is a corrupted x86_64 ELF
        # Here we only ensure that we can make the binary run and print "yes"
        #
        d = debugger([RESOLVE_EXE("CTF/technically_correct"), "notthecorrectflag"], escape_antidebug=True)

        r = d.run()

        def patch_correctness_check(t, _):
            t.regs.rbx = t.regs.rcx

        ENTRY = 0x5c7d084c137
        d.bp(ENTRY + 0x4a2, callback=patch_correctness_check, hardware=True)

        d.cont()

        self.assertEqual(r.recvline(), b"yes")

        d.kill()
        d.terminate()
