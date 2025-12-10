#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import io
import sys

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE, RESOLVE_EXE_CROSS
from libdebug import debugger
from pathlib import Path

from utils.binary_utils import PLATFORM, BASE

from libdebug.data.elf.linux_runtime_mitigations import RelroStatus

class ElfApiTest(TestCase):
    def setUp(self):
        # Redirect stdout
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput
        sys.stderr = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def test_sections_amd64(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "amd64"), aslr=False)

        sections = d.binary.sections

        self.assertEqual(len(sections), 37)

        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type, "NULL")

        #.interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x350)
        self.assertEqual(sections[1].address, 0x350)
        self.assertEqual(sections[1].size, 0x1c)
        self.assertEqual(sections[1].flags, "A")  # ALLOC
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type, "PROGBITS")

        #.note.gnu.property
        self.assertEqual(sections[2].name, ".note.gnu.property")
        self.assertEqual(sections[2].offset, 0x370)
        self.assertEqual(sections[2].address, 0x370)
        self.assertEqual(sections[2].size, 0x30)
        self.assertEqual(sections[2].flags, "A")  # ALLOC
        self.assertEqual(sections[2].address_align, 0x8)
        self.assertEqual(sections[2].section_type, "NOTE")

        #.note.gnu.build-id
        self.assertEqual(sections[3].name, ".note.gnu.build-id")
        self.assertEqual(sections[3].offset, 0x3a0)
        self.assertEqual(sections[3].address, 0x3a0)
        self.assertEqual(sections[3].size, 0x24)
        self.assertEqual(sections[3].flags, "A")  # ALLOC
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type, "NOTE")

        #.note.ABI-tag
        self.assertEqual(sections[4].name, ".note.ABI-tag")
        self.assertEqual(sections[4].offset, 0x3c4)
        self.assertEqual(sections[4].address, 0x3c4)
        self.assertEqual(sections[4].size, 0x20)
        self.assertEqual(sections[4].flags, "A")  # ALLOC
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type, "NOTE")

        #.note.weird
        self.assertEqual(sections[5].name, ".note.weird")
        self.assertEqual(sections[5].offset, 0x3e4)
        self.assertEqual(sections[5].address, 0x3e4)
        self.assertEqual(sections[5].size, 0x16)
        self.assertEqual(sections[5].flags, "A")  # ALLOC
        self.assertEqual(sections[5].address_align, 0x4)
        self.assertEqual(sections[5].section_type, "NOTE")

        #.gnu.hash
        self.assertEqual(sections[6].name, ".gnu.hash")
        self.assertEqual(sections[6].offset, 0x400)
        self.assertEqual(sections[6].address, 0x400)
        self.assertEqual(sections[6].size, 0x24)
        self.assertEqual(sections[6].flags, "A")  # ALLOC
        self.assertEqual(sections[6].address_align, 0x8)
        self.assertEqual(sections[6].section_type, "GNU_HASH")

        #.dynsym
        self.assertEqual(sections[7].name, ".dynsym")
        self.assertEqual(sections[7].offset, 0x428)
        self.assertEqual(sections[7].address, 0x428)
        self.assertEqual(sections[7].size, 0x108)
        self.assertEqual(sections[7].flags, "A")  # ALLOC
        self.assertEqual(sections[7].address_align, 0x8)
        self.assertEqual(sections[7].section_type, "DYNSYM")

        #.dynstr
        self.assertEqual(sections[8].name, ".dynstr")
        self.assertEqual(sections[8].offset, 0x530)
        self.assertEqual(sections[8].address, 0x530)
        self.assertEqual(sections[8].size, 0xeb)
        self.assertEqual(sections[8].flags, "A")  # ALLOC
        self.assertEqual(sections[8].address_align, 0x1)
        self.assertEqual(sections[8].section_type, "STRTAB")

        #.gnu.version
        self.assertEqual(sections[9].name, ".gnu.version")
        self.assertEqual(sections[9].offset, 0x61c)
        self.assertEqual(sections[9].address, 0x61c)
        self.assertEqual(sections[9].size, 0x16)
        self.assertEqual(sections[9].flags, "A")  # ALLOC
        self.assertEqual(sections[9].address_align, 0x2)
        self.assertEqual(sections[9].section_type, "GNU_VERSYM")

        #.gnu.version_r
        self.assertEqual(sections[10].name, ".gnu.version_r")
        self.assertEqual(sections[10].offset, 0x638)
        self.assertEqual(sections[10].address, 0x638)
        self.assertEqual(sections[10].size, 0x60)
        self.assertEqual(sections[10].flags, "A")  # ALLOC
        self.assertEqual(sections[10].address_align, 0x8)
        self.assertEqual(sections[10].section_type, "GNU_VERNEED")

        #.rela.dyn
        self.assertEqual(sections[11].name, ".rela.dyn")
        self.assertEqual(sections[11].offset, 0x698)
        self.assertEqual(sections[11].address, 0x698)
        self.assertEqual(sections[11].size, 0x138)
        self.assertEqual(sections[11].flags, "A")  # ALLOC
        self.assertEqual(sections[11].address_align, 0x8)
        self.assertEqual(sections[11].section_type, "RELA")

        #.rela.plt
        self.assertEqual(sections[12].name, ".rela.plt")
        self.assertEqual(sections[12].offset, 0x7d0)
        self.assertEqual(sections[12].address, 0x7d0)
        self.assertEqual(sections[12].size, 0x60)
        self.assertEqual(sections[12].flags, "AI")  # ALLOC INFOLINK
        self.assertEqual(sections[12].address_align, 0x8)
        self.assertEqual(sections[12].section_type, "RELA")

        #.init
        self.assertEqual(sections[13].name, ".init")
        self.assertEqual(sections[13].offset, 0x1000)
        self.assertEqual(sections[13].address, 0x1000)
        self.assertEqual(sections[13].size, 0x1b)
        self.assertEqual(sections[13].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[13].address_align, 0x4)
        self.assertEqual(sections[13].section_type, "PROGBITS")

        #.plt
        self.assertEqual(sections[14].name, ".plt")
        self.assertEqual(sections[14].offset, 0x1020)
        self.assertEqual(sections[14].address, 0x1020)
        self.assertEqual(sections[14].size, 0x50)
        self.assertEqual(sections[14].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[14].address_align, 0x10)
        self.assertEqual(sections[14].section_type, "PROGBITS")

        #.plt.got
        self.assertEqual(sections[15].name, ".plt.got")
        self.assertEqual(sections[15].offset, 0x1070)
        self.assertEqual(sections[15].address, 0x1070)
        self.assertEqual(sections[15].size, 0x10)
        self.assertEqual(sections[15].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[15].address_align, 0x10)
        self.assertEqual(sections[15].section_type, "PROGBITS")

        #.plt.sec
        self.assertEqual(sections[16].name, ".plt.sec")
        self.assertEqual(sections[16].offset, 0x1080)
        self.assertEqual(sections[16].address, 0x1080)
        self.assertEqual(sections[16].size, 0x40)
        self.assertEqual(sections[16].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[16].address_align, 0x10)
        self.assertEqual(sections[16].section_type, "PROGBITS")

        #.text
        self.assertEqual(sections[17].name, ".text")
        self.assertEqual(sections[17].offset, 0x10c0)
        self.assertEqual(sections[17].address, 0x10c0)
        self.assertEqual(sections[17].size, 0x27a)
        self.assertEqual(sections[17].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[17].address_align, 0x10)
        self.assertEqual(sections[17].section_type, "PROGBITS")

        #.fini
        self.assertEqual(sections[18].name, ".fini")
        self.assertEqual(sections[18].offset, 0x133c)
        self.assertEqual(sections[18].address, 0x133c)
        self.assertEqual(sections[18].size, 0xd)
        self.assertEqual(sections[18].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[18].address_align, 0x4)
        self.assertEqual(sections[18].section_type, "PROGBITS")

        #.rodata
        self.assertEqual(sections[19].name, ".rodata")
        self.assertEqual(sections[19].offset, 0x2000)
        self.assertEqual(sections[19].address, 0x2000)
        self.assertEqual(sections[19].size, 0x96)
        self.assertEqual(sections[19].flags, "A")  # ALLOC
        self.assertEqual(sections[19].address_align, 0x8)
        self.assertEqual(sections[19].section_type, "PROGBITS")

        #.eh_frame_hdr
        self.assertEqual(sections[20].name, ".eh_frame_hdr")
        self.assertEqual(sections[20].offset, 0x2098)
        self.assertEqual(sections[20].address, 0x2098)
        self.assertEqual(sections[20].size, 0x64)
        self.assertEqual(sections[20].flags, "A")  # ALLOC
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type, "PROGBITS")

        #.eh_frame
        self.assertEqual(sections[21].name, ".eh_frame")
        self.assertEqual(sections[21].offset, 0x2100)
        self.assertEqual(sections[21].address, 0x2100)
        self.assertEqual(sections[21].size, 0x138)
        self.assertEqual(sections[21].flags, "A")  # ALLOC
        self.assertEqual(sections[21].address_align, 0x8)
        self.assertEqual(sections[21].section_type, "PROGBITS")

        #.tdata
        self.assertEqual(sections[22].name, ".tdata")
        self.assertEqual(sections[22].offset, 0x2d64)
        self.assertEqual(sections[22].address, 0x3d64)
        self.assertEqual(sections[22].size, 0x4)
        self.assertEqual(sections[22].flags, "WAT")  # WRITABLE ALLOC TLS
        self.assertEqual(sections[22].address_align, 0x4)
        self.assertEqual(sections[22].section_type, "PROGBITS")

        #.tbss
        self.assertEqual(sections[23].name, ".tbss")
        self.assertEqual(sections[23].offset, 0x2d68)
        self.assertEqual(sections[23].address, 0x3d68)
        self.assertEqual(sections[23].size, 0x4)
        self.assertEqual(sections[23].flags, "WAT")  # WRITABLE ALLOC TLS
        self.assertEqual(sections[23].address_align, 0x4)
        self.assertEqual(sections[23].section_type, "NOBITS")

        #.init_array
        self.assertEqual(sections[24].name, ".init_array")
        self.assertEqual(sections[24].offset, 0x2d68)
        self.assertEqual(sections[24].address, 0x3d68)
        self.assertEqual(sections[24].size, 0x10)
        self.assertEqual(sections[24].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[24].address_align, 0x8)
        self.assertEqual(sections[24].section_type, "INIT_ARRAY")

        #.fini_array
        self.assertEqual(sections[25].name, ".fini_array")
        self.assertEqual(sections[25].offset, 0x2d78)
        self.assertEqual(sections[25].address, 0x3d78)
        self.assertEqual(sections[25].size, 0x10)
        self.assertEqual(sections[25].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[25].address_align, 0x8)
        self.assertEqual(sections[25].section_type, "FINI_ARRAY")

        #.data.rel.ro
        self.assertEqual(sections[26].name, ".data.rel.ro")
        self.assertEqual(sections[26].offset, 0x2d88)
        self.assertEqual(sections[26].address, 0x3d88)
        self.assertEqual(sections[26].size, 0x8)
        self.assertEqual(sections[26].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[26].address_align, 0x8)
        self.assertEqual(sections[26].section_type, "PROGBITS")

        #.dynamic
        self.assertEqual(sections[27].name, ".dynamic")
        self.assertEqual(sections[27].offset, 0x2d90)
        self.assertEqual(sections[27].address, 0x3d90)
        self.assertEqual(sections[27].size, 0x200)
        self.assertEqual(sections[27].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[27].address_align, 0x8)
        self.assertEqual(sections[27].section_type, "DYNAMIC")

        #.got
        self.assertEqual(sections[28].name, ".got")
        self.assertEqual(sections[28].offset, 0x2f90)
        self.assertEqual(sections[28].address, 0x3f90)
        self.assertEqual(sections[28].size, 0x70)
        self.assertEqual(sections[28].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[28].address_align, 0x8)
        self.assertEqual(sections[28].section_type, "PROGBITS")

        #.data
        self.assertEqual(sections[29].name, ".data")
        self.assertEqual(sections[29].offset, 0x3000)
        self.assertEqual(sections[29].address, 0x4000)
        self.assertEqual(sections[29].size, 0xa0)
        self.assertEqual(sections[29].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[29].address_align, 0x40)
        self.assertEqual(sections[29].section_type, "PROGBITS")

        #.extra.data
        self.assertEqual(sections[30].name, ".extra.data")
        self.assertEqual(sections[30].offset, 0x30a0)
        self.assertEqual(sections[30].address, 0x40a0)
        self.assertEqual(sections[30].size, 0x8)
        self.assertEqual(sections[30].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[30].address_align, 0x10)
        self.assertEqual(sections[30].section_type, "PROGBITS")

        #.bss
        self.assertEqual(sections[31].name, ".bss")
        self.assertEqual(sections[31].offset, 0x30a8)
        self.assertEqual(sections[31].address, 0x40c0)
        self.assertEqual(sections[31].size, 0x1140)
        self.assertEqual(sections[31].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[31].address_align, 0x20)
        self.assertEqual(sections[31].section_type, "NOBITS")

        #.comment
        self.assertEqual(sections[32].name, ".comment")
        self.assertEqual(sections[32].offset, 0x30a8)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x2b)
        self.assertEqual(sections[32].flags, "MS") # MERGE STRINGS
        self.assertEqual(sections[32].address_align, 0x1)
        self.assertEqual(sections[32].section_type, "PROGBITS")

        #.weird.debug
        self.assertEqual(sections[33].name, ".weird.debug")
        self.assertEqual(sections[33].offset, 0x30d3)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x1f)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type, "PROGBITS")

        #.symtab
        self.assertEqual(sections[34].name, ".symtab")
        self.assertEqual(sections[34].offset, 0x30f8)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x5d0)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x8)
        self.assertEqual(sections[34].section_type, "SYMTAB")

        #.strtab
        self.assertEqual(sections[35].name, ".strtab")
        self.assertEqual(sections[35].offset, 0x36c8)
        self.assertEqual(sections[35].address, 0x0)
        self.assertEqual(sections[35].size, 0x386)
        self.assertEqual(sections[35].flags, "")
        self.assertEqual(sections[35].address_align, 0x1)
        self.assertEqual(sections[35].section_type, "STRTAB")

        #.shstrtab
        self.assertEqual(sections[36].name, ".shstrtab")
        self.assertEqual(sections[36].offset, 0x3a4e)
        self.assertEqual(sections[36].address, 0x0)
        self.assertEqual(sections[36].size, 0x153)
        self.assertEqual(sections[36].flags, "")
        self.assertEqual(sections[36].address_align, 0x1)
        self.assertEqual(sections[36].section_type, "STRTAB")

        d.terminate()

    def test_dynamic_sections_amd64(self):
        """Tests the dynamic entries API for amd64."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "amd64"), aslr=False)

        dynamicSections = d.binary.dynamic_sections

        # There should be 28 dynamic entries
        self.assertEqual(len(dynamicSections), 27)

        # NEEDED libc.so.6
        self.assertEqual(dynamicSections[0].tag, "NEEDED")
        self.assertEqual(dynamicSections[0].value, "libc.so.6")
        self.assertEqual(dynamicSections[0].is_value_address, False)
        self.assertEqual(dynamicSections[0].reference_file, d.binary.absolute_path)

        # NEEDED ld-linux-x86-64.so.2
        self.assertEqual(dynamicSections[1].tag, "NEEDED")
        self.assertEqual(dynamicSections[1].value, "ld-linux-x86-64.so.2")
        self.assertEqual(dynamicSections[1].is_value_address, False)
        self.assertEqual(dynamicSections[1].reference_file, d.binary.absolute_path)

        # INIT / FINI
        self.assertEqual(dynamicSections[2].tag, "INIT")
        self.assertEqual(dynamicSections[2].value, 0x1000)
        self.assertTrue(dynamicSections[2].is_value_address)

        self.assertEqual(dynamicSections[3].tag, "FINI")
        self.assertEqual(dynamicSections[3].value, 0x133c)
        self.assertTrue(dynamicSections[3].is_value_address)

        # INIT_ARRAY / INIT_ARRAYSZ / FINI_ARRAY / FINI_ARRAYSZ
        self.assertEqual(dynamicSections[4].tag, "INIT_ARRAY")
        self.assertEqual(dynamicSections[4].value, 0x3d68)
        self.assertTrue(dynamicSections[4].is_value_address)

        self.assertEqual(dynamicSections[5].tag, "INIT_ARRAYSZ")
        self.assertEqual(dynamicSections[5].value, 16)

        self.assertEqual(dynamicSections[6].tag, "FINI_ARRAY")
        self.assertEqual(dynamicSections[6].value, 0x3d78)
        self.assertTrue(dynamicSections[6].is_value_address)

        self.assertEqual(dynamicSections[7].tag, "FINI_ARRAYSZ")
        self.assertEqual(dynamicSections[7].value, 16)

        # GNU_HASH / STRTAB / SYMTAB / STRSZ / SYMENT
        self.assertEqual(dynamicSections[8].tag, "GNU_HASH")
        self.assertEqual(dynamicSections[8].value, 0x400)
        self.assertTrue(dynamicSections[8].is_value_address)

        self.assertEqual(dynamicSections[9].tag, "STRTAB")
        self.assertEqual(dynamicSections[9].value, 0x530)
        self.assertTrue(dynamicSections[9].is_value_address)

        self.assertEqual(dynamicSections[10].tag, "SYMTAB")
        self.assertEqual(dynamicSections[10].value, 0x428)
        self.assertTrue(dynamicSections[10].is_value_address)

        self.assertEqual(dynamicSections[11].tag, "STRSZ")
        self.assertEqual(dynamicSections[11].value, 235)

        self.assertEqual(dynamicSections[12].tag, "SYMENT")
        self.assertEqual(dynamicSections[12].value, 24)

        # DEBUG
        self.assertEqual(dynamicSections[13].tag, "DEBUG")
        self.assertEqual(dynamicSections[13].value, 0x0)

        # PLTGOT / PLTRELSZ / PLTREL / JMPREL
        self.assertEqual(dynamicSections[14].tag, "PLTGOT")
        self.assertEqual(dynamicSections[14].value, 0x3f90)
        self.assertTrue(dynamicSections[14].is_value_address)

        self.assertEqual(dynamicSections[15].tag, "PLTRELSZ")
        self.assertEqual(dynamicSections[15].value, 96)

        self.assertEqual(dynamicSections[16].tag, "PLTREL")
        self.assertEqual(dynamicSections[16].value, "RELA")

        self.assertEqual(dynamicSections[17].tag, "JMPREL")
        self.assertEqual(dynamicSections[17].value, 0x7d0)
        self.assertTrue(dynamicSections[17].is_value_address)

        # RELA / RELASZ / RELAENT
        self.assertEqual(dynamicSections[18].tag, "RELA")
        self.assertEqual(dynamicSections[18].value, 0x698)
        self.assertTrue(dynamicSections[18].is_value_address)

        self.assertEqual(dynamicSections[19].tag, "RELASZ")
        self.assertEqual(dynamicSections[19].value, 312)

        self.assertEqual(dynamicSections[20].tag, "RELAENT")
        self.assertEqual(dynamicSections[20].value, 24)

        # FLAGS / FLAGS_1
        self.assertEqual(dynamicSections[21].tag, "FLAGS")
        self.assertEqual(dynamicSections[21].value, "BIND_NOW")

        self.assertEqual(dynamicSections[22].tag, "FLAGS_1")
        self.assertEqual(dynamicSections[22].value, "NOW PIE")

        # VERNEED / VERNEEDNUM / VERSYM
        self.assertEqual(dynamicSections[23].tag, "VERNEED")
        self.assertEqual(dynamicSections[23].value, 0x638)
        self.assertTrue(dynamicSections[23].is_value_address)

        self.assertEqual(dynamicSections[24].tag, "VERNEEDNUM")
        self.assertEqual(dynamicSections[24].value, 2)

        self.assertEqual(dynamicSections[25].tag, "VERSYM")
        self.assertEqual(dynamicSections[25].value, 0x61c)
        self.assertTrue(dynamicSections[25].is_value_address)

        # RELACOUNT
        self.assertEqual(dynamicSections[26].tag, "RELACOUNT")
        self.assertEqual(dynamicSections[26].value, 7)

        d.terminate()

    def test_program_headers_amd64(self):
        """Tests the program headers API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "amd64"), aslr=False)

        program_headers = d.binary.program_headers

        # There should be 14 program headers
        self.assertEqual(len(program_headers), 14)

        # PHDR
        self.assertEqual(program_headers[0].header_type, "PHDR")
        self.assertEqual(program_headers[0].offset, 0x40)
        self.assertEqual(program_headers[0].vaddr, 0x40)
        self.assertEqual(program_headers[0].paddr, 0x40)
        self.assertEqual(program_headers[0].filesz, 0x310)
        self.assertEqual(program_headers[0].memsz, 0x310)
        self.assertEqual(program_headers[0].flags, "R")
        self.assertEqual(program_headers[0].align, 0x8)
        self.assertEqual(program_headers[0].reference_file, d.binary.absolute_path)

        # INTERP
        self.assertEqual(program_headers[1].header_type, "INTERP")
        self.assertEqual(program_headers[1].offset, 0x350)
        self.assertEqual(program_headers[1].vaddr, 0x350)
        self.assertEqual(program_headers[1].paddr, 0x350)
        self.assertEqual(program_headers[1].filesz, 0x1c)
        self.assertEqual(program_headers[1].memsz, 0x1c)
        self.assertEqual(program_headers[1].flags, "R")
        self.assertEqual(program_headers[1].align, 0x1)
        self.assertEqual(program_headers[1].reference_file, d.binary.absolute_path)

        # LOAD (first)
        self.assertEqual(program_headers[2].header_type, "LOAD")
        self.assertEqual(program_headers[2].offset, 0x0)
        self.assertEqual(program_headers[2].vaddr, 0x0)
        self.assertEqual(program_headers[2].paddr, 0x0)
        self.assertEqual(program_headers[2].filesz, 0x830)
        self.assertEqual(program_headers[2].memsz, 0x830)
        self.assertEqual(program_headers[2].flags, "R")
        self.assertEqual(program_headers[2].align, 0x1000)
        self.assertEqual(program_headers[2].reference_file, d.binary.absolute_path)

        # LOAD (second)
        self.assertEqual(program_headers[3].header_type, "LOAD")
        self.assertEqual(program_headers[3].offset, 0x1000)
        self.assertEqual(program_headers[3].vaddr, 0x1000)
        self.assertEqual(program_headers[3].paddr, 0x1000)
        self.assertEqual(program_headers[3].filesz, 0x349)
        self.assertEqual(program_headers[3].memsz, 0x349)
        self.assertEqual(program_headers[3].flags, "RX")
        self.assertEqual(program_headers[3].align, 0x1000)
        self.assertEqual(program_headers[3].reference_file, d.binary.absolute_path)

        # LOAD (third)
        self.assertEqual(program_headers[4].header_type, "LOAD")
        self.assertEqual(program_headers[4].offset, 0x2000)
        self.assertEqual(program_headers[4].vaddr, 0x2000)
        self.assertEqual(program_headers[4].paddr, 0x2000)
        self.assertEqual(program_headers[4].filesz, 0x238)
        self.assertEqual(program_headers[4].memsz, 0x238)
        self.assertEqual(program_headers[4].flags, "R")
        self.assertEqual(program_headers[4].align, 0x1000)
        self.assertEqual(program_headers[4].reference_file, d.binary.absolute_path)

        # LOAD (fourth)
        self.assertEqual(program_headers[5].header_type, "LOAD")
        self.assertEqual(program_headers[5].offset, 0x2d64)
        self.assertEqual(program_headers[5].vaddr, 0x3d64)
        self.assertEqual(program_headers[5].paddr, 0x3d64)
        self.assertEqual(program_headers[5].filesz, 0x344)
        self.assertEqual(program_headers[5].memsz, 0x149c)
        self.assertEqual(program_headers[5].flags, "RW")
        self.assertEqual(program_headers[5].align, 0x1000)
        self.assertEqual(program_headers[5].reference_file, d.binary.absolute_path)

        # DYNAMIC
        self.assertEqual(program_headers[6].header_type, "DYNAMIC")
        self.assertEqual(program_headers[6].offset, 0x2d90)
        self.assertEqual(program_headers[6].vaddr, 0x3d90)
        self.assertEqual(program_headers[6].paddr, 0x3d90)
        self.assertEqual(program_headers[6].filesz, 0x200)
        self.assertEqual(program_headers[6].memsz, 0x200)
        self.assertEqual(program_headers[6].flags, "RW")
        self.assertEqual(program_headers[6].align, 0x8)
        self.assertEqual(program_headers[6].reference_file, d.binary.absolute_path)

        # NOTE (first)
        self.assertEqual(program_headers[7].header_type, "NOTE")
        self.assertEqual(program_headers[7].offset, 0x370)
        self.assertEqual(program_headers[7].vaddr, 0x370)
        self.assertEqual(program_headers[7].paddr, 0x370)
        self.assertEqual(program_headers[7].filesz, 0x30)
        self.assertEqual(program_headers[7].memsz, 0x30)
        self.assertEqual(program_headers[7].flags, "R")
        self.assertEqual(program_headers[7].align, 0x8)
        self.assertEqual(program_headers[7].reference_file, d.binary.absolute_path)

        # NOTE (second)
        self.assertEqual(program_headers[8].header_type, "NOTE")
        self.assertEqual(program_headers[8].offset, 0x3a0)
        self.assertEqual(program_headers[8].vaddr, 0x3a0)
        self.assertEqual(program_headers[8].paddr, 0x3a0)
        self.assertEqual(program_headers[8].filesz, 0x5a)
        self.assertEqual(program_headers[8].memsz, 0x5a)
        self.assertEqual(program_headers[8].flags, "R")
        self.assertEqual(program_headers[8].align, 0x4)
        self.assertEqual(program_headers[8].reference_file, d.binary.absolute_path)

        # TLS
        self.assertEqual(program_headers[9].header_type, "TLS")
        self.assertEqual(program_headers[9].offset, 0x2d64)
        self.assertEqual(program_headers[9].vaddr, 0x3d64)
        self.assertEqual(program_headers[9].paddr, 0x3d64)
        self.assertEqual(program_headers[9].filesz, 0x4)
        self.assertEqual(program_headers[9].memsz, 0x8)
        self.assertEqual(program_headers[9].flags, "R")
        self.assertEqual(program_headers[9].align, 0x4)
        self.assertEqual(program_headers[9].reference_file, d.binary.absolute_path)

        # GNU_PROPERTY
        self.assertEqual(program_headers[10].header_type, "GNU_PROPERTY")
        self.assertEqual(program_headers[10].offset, 0x370)
        self.assertEqual(program_headers[10].vaddr, 0x370)
        self.assertEqual(program_headers[10].paddr, 0x370)
        self.assertEqual(program_headers[10].filesz, 0x30)
        self.assertEqual(program_headers[10].memsz, 0x30)
        self.assertEqual(program_headers[10].flags, "R")
        self.assertEqual(program_headers[10].align, 0x8)
        self.assertEqual(program_headers[10].reference_file, d.binary.absolute_path)

        # GNU_EH_FRAME
        self.assertEqual(program_headers[11].header_type, "GNU_EH_FRAME")
        self.assertEqual(program_headers[11].offset, 0x2098)
        self.assertEqual(program_headers[11].vaddr, 0x2098)
        self.assertEqual(program_headers[11].paddr, 0x2098)
        self.assertEqual(program_headers[11].filesz, 0x64)
        self.assertEqual(program_headers[11].memsz, 0x64)
        self.assertEqual(program_headers[11].flags, "R")
        self.assertEqual(program_headers[11].align, 0x4)
        self.assertEqual(program_headers[11].reference_file, d.binary.absolute_path)

        # GNU_STACK
        self.assertEqual(program_headers[12].header_type, "GNU_STACK")
        self.assertEqual(program_headers[12].offset, 0x0)
        self.assertEqual(program_headers[12].vaddr, 0x0)
        self.assertEqual(program_headers[12].paddr, 0x0)
        self.assertEqual(program_headers[12].filesz, 0x0)
        self.assertEqual(program_headers[12].memsz, 0x0)
        self.assertEqual(program_headers[12].flags, "RW")
        self.assertEqual(program_headers[12].align, 0x10)
        self.assertEqual(program_headers[12].reference_file, d.binary.absolute_path)

        # GNU_RELRO
        self.assertEqual(program_headers[13].header_type, "GNU_RELRO")
        self.assertEqual(program_headers[13].offset, 0x2d64)
        self.assertEqual(program_headers[13].vaddr, 0x3d64)
        self.assertEqual(program_headers[13].paddr, 0x3d64)
        self.assertEqual(program_headers[13].filesz, 0x29c)
        self.assertEqual(program_headers[13].memsz, 0x29c)
        self.assertEqual(program_headers[13].flags, "R")
        self.assertEqual(program_headers[13].align, 0x1)
        self.assertEqual(program_headers[13].reference_file, d.binary.absolute_path)

        d.terminate()
    
    def test_gnu_properties_amd64(self):
        """Tests the GNU features API for amd64."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "amd64"), aslr=False)

        gnu_properties = d.binary.gnu_properties

        # There should be 2 GNU features
        self.assertEqual(len(gnu_properties), 2)

        # Feature 1
        self.assertEqual(gnu_properties[0].pr_type, "X86_FEATURE_1_AND")
        self.assertEqual(gnu_properties[0].value, "IBT SHSTK")

        # Feature 2
        self.assertEqual(gnu_properties[1].pr_type, "X86_ISA_1_NEEDED")
        self.assertEqual(gnu_properties[1].value, "BASELINE")

        d.terminate()

    def test_sections_aarch64(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "aarch64"), aslr=False)

        sections = d.binary.sections

        self.assertEqual(len(sections), 35)

        # NULL
        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type, "NULL")

        # .interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x2a8)
        self.assertEqual(sections[1].address, 0x2a8)
        self.assertEqual(sections[1].size, 0x1b)
        self.assertEqual(sections[1].flags, "A")
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type, "PROGBITS")

        # .note.weird
        self.assertEqual(sections[2].name, ".note.weird")
        self.assertEqual(sections[2].offset, 0x2d0)
        self.assertEqual(sections[2].address, 0x2d0)
        self.assertEqual(sections[2].size, 0x16)
        self.assertEqual(sections[2].flags, "A")
        self.assertEqual(sections[2].address_align, 0x10)
        self.assertEqual(sections[2].section_type, "NOTE")

        # .note.gnu.build-id
        self.assertEqual(sections[3].name, ".note.gnu.build-id")
        self.assertEqual(sections[3].offset, 0x2e8)
        self.assertEqual(sections[3].address, 0x2e8)
        self.assertEqual(sections[3].size, 0x24)
        self.assertEqual(sections[3].flags, "A")
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type, "NOTE")

        # .note.ABI-tag
        self.assertEqual(sections[4].name, ".note.ABI-tag")
        self.assertEqual(sections[4].offset, 0x30c)
        self.assertEqual(sections[4].address, 0x30c)
        self.assertEqual(sections[4].size, 0x20)
        self.assertEqual(sections[4].flags, "A")
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type, "NOTE")

        # .gnu.hash
        self.assertEqual(sections[5].name, ".gnu.hash")
        self.assertEqual(sections[5].offset, 0x330)
        self.assertEqual(sections[5].address, 0x330)
        self.assertEqual(sections[5].size, 0x1c)
        self.assertEqual(sections[5].flags, "A")
        self.assertEqual(sections[5].address_align, 0x8)
        self.assertEqual(sections[5].section_type, "GNU_HASH")

        # .dynsym
        self.assertEqual(sections[6].name, ".dynsym")
        self.assertEqual(sections[6].offset, 0x350)
        self.assertEqual(sections[6].address, 0x350)
        self.assertEqual(sections[6].size, 0x138)
        self.assertEqual(sections[6].flags, "A")
        self.assertEqual(sections[6].address_align, 0x8)
        self.assertEqual(sections[6].section_type, "DYNSYM")

        # .dynstr
        self.assertEqual(sections[7].name, ".dynstr")
        self.assertEqual(sections[7].offset, 0x488)
        self.assertEqual(sections[7].address, 0x488)
        self.assertEqual(sections[7].size, 0x0a3)
        self.assertEqual(sections[7].flags, "A")
        self.assertEqual(sections[7].address_align, 0x1)
        self.assertEqual(sections[7].section_type, "STRTAB")

        # .gnu.version
        self.assertEqual(sections[8].name, ".gnu.version")
        self.assertEqual(sections[8].offset, 0x52c)
        self.assertEqual(sections[8].address, 0x52c)
        self.assertEqual(sections[8].size, 0x1a)
        self.assertEqual(sections[8].flags, "A")
        self.assertEqual(sections[8].address_align, 0x2)
        self.assertEqual(sections[8].section_type, "GNU_VERSYM")

        # .gnu.version_r
        self.assertEqual(sections[9].name, ".gnu.version_r")
        self.assertEqual(sections[9].offset, 0x548)
        self.assertEqual(sections[9].address, 0x548)
        self.assertEqual(sections[9].size, 0x30)
        self.assertEqual(sections[9].flags, "A")
        self.assertEqual(sections[9].address_align, 0x8)
        self.assertEqual(sections[9].section_type, "GNU_VERNEED")

        # .rela.dyn
        self.assertEqual(sections[10].name, ".rela.dyn")
        self.assertEqual(sections[10].offset, 0x578)
        self.assertEqual(sections[10].address, 0x578)
        self.assertEqual(sections[10].size, 0x180)
        self.assertEqual(sections[10].flags, "A")
        self.assertEqual(sections[10].address_align, 0x8)
        self.assertEqual(sections[10].section_type, "RELA")

        # .rela.plt
        self.assertEqual(sections[11].name, ".rela.plt")
        self.assertEqual(sections[11].offset, 0x6f8)
        self.assertEqual(sections[11].address, 0x6f8)
        self.assertEqual(sections[11].size, 0xa8)
        self.assertEqual(sections[11].flags, "AI")
        self.assertEqual(sections[11].address_align, 0x8)
        self.assertEqual(sections[11].section_type, "RELA")

        # .init
        self.assertEqual(sections[12].name, ".init")
        self.assertEqual(sections[12].offset, 0x7a0)
        self.assertEqual(sections[12].address, 0x7a0)
        self.assertEqual(sections[12].size, 0x18)
        self.assertEqual(sections[12].flags, "AX")
        self.assertEqual(sections[12].address_align, 0x4)
        self.assertEqual(sections[12].section_type, "PROGBITS")

        # .plt
        self.assertEqual(sections[13].name, ".plt")
        self.assertEqual(sections[13].offset, 0x7c0)
        self.assertEqual(sections[13].address, 0x7c0)
        self.assertEqual(sections[13].size, 0x90)
        self.assertEqual(sections[13].flags, "AX")
        self.assertEqual(sections[13].address_align, 0x10)
        self.assertEqual(sections[13].section_type, "PROGBITS")

        # .text
        self.assertEqual(sections[14].name, ".text")
        self.assertEqual(sections[14].offset, 0x880)
        self.assertEqual(sections[14].address, 0x880)
        self.assertEqual(sections[14].size, 0x2f8)
        self.assertEqual(sections[14].flags, "AX")
        self.assertEqual(sections[14].address_align, 0x40)
        self.assertEqual(sections[14].section_type, "PROGBITS")

        # .fini
        self.assertEqual(sections[15].name, ".fini")
        self.assertEqual(sections[15].offset, 0xb78)
        self.assertEqual(sections[15].address, 0xb78)
        self.assertEqual(sections[15].size, 0x14)
        self.assertEqual(sections[15].flags, "AX")
        self.assertEqual(sections[15].address_align, 0x4)
        self.assertEqual(sections[15].section_type, "PROGBITS")

        # .rodata
        self.assertEqual(sections[16].name, ".rodata")
        self.assertEqual(sections[16].offset, 0xb90)
        self.assertEqual(sections[16].address, 0xb90)
        self.assertEqual(sections[16].size, 0xa6)
        self.assertEqual(sections[16].flags, "A")
        self.assertEqual(sections[16].address_align, 0x8)
        self.assertEqual(sections[16].section_type, "PROGBITS")

        # .eh_frame_hdr
        self.assertEqual(sections[17].name, ".eh_frame_hdr")
        self.assertEqual(sections[17].offset, 0xc38)
        self.assertEqual(sections[17].address, 0xc38)
        self.assertEqual(sections[17].size, 0x64)
        self.assertEqual(sections[17].flags, "A")
        self.assertEqual(sections[17].address_align, 0x4)
        self.assertEqual(sections[17].section_type, "PROGBITS")

        # .eh_frame
        self.assertEqual(sections[18].name, ".eh_frame")
        self.assertEqual(sections[18].offset, 0xca0)
        self.assertEqual(sections[18].address, 0xca0)
        self.assertEqual(sections[18].size, 0x124)
        self.assertEqual(sections[18].flags, "A")
        self.assertEqual(sections[18].address_align, 0x8)
        self.assertEqual(sections[18].section_type, "PROGBITS")

        # .tdata
        self.assertEqual(sections[19].name, ".tdata")
        self.assertEqual(sections[19].offset, 0xfd84)
        self.assertEqual(sections[19].address, 0x1fd84)
        self.assertEqual(sections[19].size, 0x4)
        self.assertEqual(sections[19].flags, "WAT")
        self.assertEqual(sections[19].address_align, 0x4)
        self.assertEqual(sections[19].section_type, "PROGBITS")

        # .tbss
        self.assertEqual(sections[20].name, ".tbss")
        self.assertEqual(sections[20].offset, 0xfd88)
        self.assertEqual(sections[20].address, 0x1fd88)
        self.assertEqual(sections[20].size, 0x4)
        self.assertEqual(sections[20].flags, "WAT")
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type, "NOBITS")

        # .init_array
        self.assertEqual(sections[21].name, ".init_array")
        self.assertEqual(sections[21].offset, 0xfd88)
        self.assertEqual(sections[21].address, 0x1fd88)
        self.assertEqual(sections[21].size, 0x10)
        self.assertEqual(sections[21].flags, "WA")
        self.assertEqual(sections[21].address_align, 0x8)
        self.assertEqual(sections[21].section_type, "INIT_ARRAY")

        # .fini_array
        self.assertEqual(sections[22].name, ".fini_array")
        self.assertEqual(sections[22].offset, 0xfd98)
        self.assertEqual(sections[22].address, 0x1fd98)
        self.assertEqual(sections[22].size, 0x10)
        self.assertEqual(sections[22].flags, "WA")
        self.assertEqual(sections[22].address_align, 0x8)
        self.assertEqual(sections[22].section_type, "FINI_ARRAY")

        # .data.rel.ro
        self.assertEqual(sections[23].name, ".data.rel.ro")
        self.assertEqual(sections[23].offset, 0xfda8)
        self.assertEqual(sections[23].address, 0x1fda8)
        self.assertEqual(sections[23].size, 0x8)
        self.assertEqual(sections[23].flags, "WA")
        self.assertEqual(sections[23].address_align, 0x8)
        self.assertEqual(sections[23].section_type, "PROGBITS")

        # .dynamic
        self.assertEqual(sections[24].name, ".dynamic")
        self.assertEqual(sections[24].offset, 0xfdb0)
        self.assertEqual(sections[24].address, 0x1fdb0)
        self.assertEqual(sections[24].size, 0x1e0)
        self.assertEqual(sections[24].flags, "WA")
        self.assertEqual(sections[24].address_align, 0x8)
        self.assertEqual(sections[24].section_type, "DYNAMIC")

        # .got
        self.assertEqual(sections[25].name, ".got")
        self.assertEqual(sections[25].offset, 0xff90)
        self.assertEqual(sections[25].address, 0x1ff90)
        self.assertEqual(sections[25].size, 0x58)
        self.assertEqual(sections[25].flags, "WA")
        self.assertEqual(sections[25].address_align, 0x8)
        self.assertEqual(sections[25].section_type, "PROGBITS")

        # .got.plt
        self.assertEqual(sections[26].name, ".got.plt")
        self.assertEqual(sections[26].offset, 0xffe8)
        self.assertEqual(sections[26].address, 0x1ffe8)
        self.assertEqual(sections[26].size, 0x50)
        self.assertEqual(sections[26].flags, "WA")
        self.assertEqual(sections[26].address_align, 0x8)
        self.assertEqual(sections[26].section_type, "PROGBITS")

        # .data
        self.assertEqual(sections[27].name, ".data")
        self.assertEqual(sections[27].offset, 0x10040)
        self.assertEqual(sections[27].address, 0x20040)
        self.assertEqual(sections[27].size, 0xa0)
        self.assertEqual(sections[27].flags, "WA")
        self.assertEqual(sections[27].address_align, 0x40)
        self.assertEqual(sections[27].section_type, "PROGBITS")

        # .extra.data
        self.assertEqual(sections[28].name, ".extra.data")
        self.assertEqual(sections[28].offset, 0x20000)
        self.assertEqual(sections[28].address, 0x30000)
        self.assertEqual(sections[28].size, 0x8)
        self.assertEqual(sections[28].flags, "WA")
        self.assertEqual(sections[28].address_align, 0x10000)
        self.assertEqual(sections[28].section_type, "PROGBITS")

        # .bss
        self.assertEqual(sections[29].name, ".bss")
        self.assertEqual(sections[29].offset, 0x20008)
        self.assertEqual(sections[29].address, 0x30008)
        self.assertEqual(sections[29].size, 0x1120)
        self.assertEqual(sections[29].flags, "WA")
        self.assertEqual(sections[29].address_align, 0x8)
        self.assertEqual(sections[29].section_type, "NOBITS")

        # .comment
        self.assertEqual(sections[30].name, ".comment")
        self.assertEqual(sections[30].offset, 0x20008)
        self.assertEqual(sections[30].address, 0x0)
        self.assertEqual(sections[30].size, 0x27)
        self.assertEqual(sections[30].flags, "MS")
        self.assertEqual(sections[30].address_align, 0x1)
        self.assertEqual(sections[30].section_type, "PROGBITS")

        # .weird.debug
        self.assertEqual(sections[31].name, ".weird.debug")
        self.assertEqual(sections[31].offset, 0x2002f)
        self.assertEqual(sections[31].address, 0x0)
        self.assertEqual(sections[31].size, 0x1f)
        self.assertEqual(sections[31].flags, "")
        self.assertEqual(sections[31].address_align, 0x1)
        self.assertEqual(sections[31].section_type, "PROGBITS")

        # .symtab
        self.assertEqual(sections[32].name, ".symtab")
        self.assertEqual(sections[32].offset, 0x20050)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x0cd8)
        self.assertEqual(sections[32].flags, "")
        self.assertEqual(sections[32].address_align, 0x8)
        self.assertEqual(sections[32].section_type, "SYMTAB")

        # .strtab
        self.assertEqual(sections[33].name, ".strtab")
        self.assertEqual(sections[33].offset, 0x20d28)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x038d)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type, "STRTAB")

        # .shstrtab
        self.assertEqual(sections[34].name, ".shstrtab")
        self.assertEqual(sections[34].offset, 0x210b5)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x013c)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x1)
        self.assertEqual(sections[34].section_type, "STRTAB")

        d.terminate()

    def test_dynamic_sections_aarch64(self):
        """Tests the dynamic sections API for aarch64."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "aarch64"), aslr=False)

        dynamic_sections = d.binary.dynamic_sections

        # There should be 16 dynamic sections
        self.assertEqual(len(dynamic_sections), 25)

        # Check some dynamic section entries
        # NEEDED libc.so.6
        self.assertEqual(dynamic_sections[0].tag, "NEEDED")
        self.assertEqual(dynamic_sections[0].value, "libc.so.6")
        self.assertEqual(dynamic_sections[0].is_value_address, False)
        self.assertEqual(dynamic_sections[0].reference_file, d.binary.absolute_path)

        # INIT / FINI
        self.assertEqual(dynamic_sections[1].tag, "INIT")
        self.assertEqual(dynamic_sections[1].value, 0x7a0)
        self.assertTrue(dynamic_sections[1].is_value_address)

        self.assertEqual(dynamic_sections[2].tag, "FINI")
        self.assertEqual(dynamic_sections[2].value, 0xb78)
        self.assertTrue(dynamic_sections[2].is_value_address)

        # INIT_ARRAY / INIT_ARRAYSZ / FINI_ARRAY / FINI_ARRAYSZ
        self.assertEqual(dynamic_sections[3].tag, "INIT_ARRAY")
        self.assertEqual(dynamic_sections[3].value, 0x1fd88)
        self.assertTrue(dynamic_sections[3].is_value_address)

        self.assertEqual(dynamic_sections[4].tag, "INIT_ARRAYSZ")
        self.assertEqual(dynamic_sections[4].value, 16)

        self.assertEqual(dynamic_sections[5].tag, "FINI_ARRAY")
        self.assertEqual(dynamic_sections[5].value, 0x1fd98)
        self.assertTrue(dynamic_sections[5].is_value_address)

        self.assertEqual(dynamic_sections[6].tag, "FINI_ARRAYSZ")
        self.assertEqual(dynamic_sections[6].value, 16)

        # GNU_HASH / STRTAB / SYMTAB / STRSZ / SYMENT
        self.assertEqual(dynamic_sections[7].tag, "GNU_HASH")
        self.assertEqual(dynamic_sections[7].value, 0x330)
        self.assertTrue(dynamic_sections[7].is_value_address)

        self.assertEqual(dynamic_sections[8].tag, "STRTAB")
        self.assertEqual(dynamic_sections[8].value, 0x488)
        self.assertTrue(dynamic_sections[8].is_value_address)

        self.assertEqual(dynamic_sections[9].tag, "SYMTAB")
        self.assertEqual(dynamic_sections[9].value, 0x350)
        self.assertTrue(dynamic_sections[9].is_value_address)

        self.assertEqual(dynamic_sections[10].tag, "STRSZ")
        self.assertEqual(dynamic_sections[10].value, 163)

        self.assertEqual(dynamic_sections[11].tag, "SYMENT")
        self.assertEqual(dynamic_sections[11].value, 24)

        # DEBUG
        self.assertEqual(dynamic_sections[12].tag, "DEBUG")
        self.assertEqual(dynamic_sections[12].value, 0x0)

        # PLTGOT / PLTRELSZ / PLTREL / JMPREL
        self.assertEqual(dynamic_sections[13].tag, "PLTGOT")
        self.assertEqual(dynamic_sections[13].value, 0x1ffe8)
        self.assertTrue(dynamic_sections[13].is_value_address)

        self.assertEqual(dynamic_sections[14].tag, "PLTRELSZ")
        self.assertEqual(dynamic_sections[14].value, 168)

        self.assertEqual(dynamic_sections[15].tag, "PLTREL")
        self.assertEqual(dynamic_sections[15].value, "RELA")

        self.assertEqual(dynamic_sections[16].tag, "JMPREL")
        self.assertEqual(dynamic_sections[16].value, 0x6f8)
        self.assertTrue(dynamic_sections[16].is_value_address)

        # RELA / RELASZ / RELAENT
        self.assertEqual(dynamic_sections[17].tag, "RELA")
        self.assertEqual(dynamic_sections[17].value, 0x578)
        self.assertTrue(dynamic_sections[17].is_value_address)

        self.assertEqual(dynamic_sections[18].tag, "RELASZ")
        self.assertEqual(dynamic_sections[18].value, 384)

        self.assertEqual(dynamic_sections[19].tag, "RELAENT")
        self.assertEqual(dynamic_sections[19].value, 24)

        # FLAGS_1
        self.assertEqual(dynamic_sections[20].tag, "FLAGS_1")
        self.assertEqual(dynamic_sections[20].value, "PIE")

        # VERNEED / VERNEEDNUM / VERSYM
        self.assertEqual(dynamic_sections[21].tag, "VERNEED")
        self.assertEqual(dynamic_sections[21].value, 0x548)
        self.assertTrue(dynamic_sections[21].is_value_address)

        self.assertEqual(dynamic_sections[22].tag, "VERNEEDNUM")
        self.assertEqual(dynamic_sections[22].value, 1)

        self.assertEqual(dynamic_sections[23].tag, "VERSYM")
        self.assertEqual(dynamic_sections[23].value, 0x52c)
        self.assertTrue(dynamic_sections[23].is_value_address)

        # RELACOUNT
        self.assertEqual(dynamic_sections[24].tag, "RELACOUNT")
        self.assertEqual(dynamic_sections[24].value, 11)

        d.terminate()

    def test_program_headers_aarch64(self):
        """Tests the program headers API for aarch64."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "aarch64"), aslr=False)

        program_headers = d.binary.program_headers

        self.assertEqual(len(program_headers), 11)

        # PT_PHDR
        self.assertEqual(program_headers[0].header_type, "PHDR")
        self.assertEqual(program_headers[0].offset, 0x40)
        self.assertEqual(program_headers[0].vaddr, 0x40)
        self.assertEqual(program_headers[0].paddr, 0x40)
        self.assertEqual(program_headers[0].filesz, 0x268)
        self.assertEqual(program_headers[0].memsz, 0x268)
        self.assertEqual(program_headers[0].flags, "R")
        self.assertEqual(program_headers[0].align, 0x8)
        self.assertEqual(program_headers[0].reference_file, d.binary.absolute_path)

        # INTERP
        self.assertEqual(program_headers[1].header_type, "INTERP")
        self.assertEqual(program_headers[1].offset, 0x2a8)
        self.assertEqual(program_headers[1].vaddr, 0x2a8)
        self.assertEqual(program_headers[1].paddr, 0x2a8)
        self.assertEqual(program_headers[1].filesz, 0x1b)
        self.assertEqual(program_headers[1].memsz, 0x1b)
        self.assertEqual(program_headers[1].flags, "R")
        self.assertEqual(program_headers[1].align, 0x1)
        self.assertEqual(program_headers[1].reference_file, d.binary.absolute_path)

        # LOAD (first)
        self.assertEqual(program_headers[2].header_type, "LOAD")
        self.assertEqual(program_headers[2].offset, 0x0)
        self.assertEqual(program_headers[2].vaddr, 0x0)
        self.assertEqual(program_headers[2].paddr, 0x0)
        self.assertEqual(program_headers[2].filesz, 0xdc4)
        self.assertEqual(program_headers[2].memsz, 0xdc4)
        self.assertEqual(program_headers[2].flags, "RX")
        self.assertEqual(program_headers[2].align, 0x10000)
        self.assertEqual(program_headers[2].reference_file, d.binary.absolute_path)

        # LOAD (second)
        self.assertEqual(program_headers[3].header_type, "LOAD")
        self.assertEqual(program_headers[3].offset, 0xfd84)
        self.assertEqual(program_headers[3].vaddr, 0x1fd84)
        self.assertEqual(program_headers[3].paddr, 0x1fd84)
        self.assertEqual(program_headers[3].filesz, 0x10284)
        self.assertEqual(program_headers[3].memsz, 0x113a4)
        self.assertEqual(program_headers[3].flags, "RW")
        self.assertEqual(program_headers[3].align, 0x10000)
        self.assertEqual(program_headers[3].reference_file, d.binary.absolute_path)

        # DYNAMIC
        self.assertEqual(program_headers[4].header_type, "DYNAMIC")
        self.assertEqual(program_headers[4].offset, 0xfdb0)
        self.assertEqual(program_headers[4].vaddr, 0x1fdb0)
        self.assertEqual(program_headers[4].paddr, 0x1fdb0)
        self.assertEqual(program_headers[4].filesz, 0x1e0)
        self.assertEqual(program_headers[4].memsz, 0x1e0)
        self.assertEqual(program_headers[4].flags, "RW")
        self.assertEqual(program_headers[4].align, 0x8)
        self.assertEqual(program_headers[4].reference_file, d.binary.absolute_path)

        # NOTE (first)
        self.assertEqual(program_headers[5].header_type, "NOTE")
        self.assertEqual(program_headers[5].offset, 0x2d0)
        self.assertEqual(program_headers[5].vaddr, 0x2d0)
        self.assertEqual(program_headers[5].paddr, 0x2d0)
        self.assertEqual(program_headers[5].filesz, 0x16)
        self.assertEqual(program_headers[5].memsz, 0x16)
        self.assertEqual(program_headers[5].flags, "R")
        self.assertEqual(program_headers[5].align, 0x10)
        self.assertEqual(program_headers[5].reference_file, d.binary.absolute_path)

        # NOTE (second)
        self.assertEqual(program_headers[6].header_type, "NOTE")
        self.assertEqual(program_headers[6].offset, 0x2e8)
        self.assertEqual(program_headers[6].vaddr, 0x2e8)
        self.assertEqual(program_headers[6].paddr, 0x2e8)
        self.assertEqual(program_headers[6].filesz, 0x44)
        self.assertEqual(program_headers[6].memsz, 0x44)
        self.assertEqual(program_headers[6].flags, "R")
        self.assertEqual(program_headers[6].align, 0x4)
        self.assertEqual(program_headers[6].reference_file, d.binary.absolute_path)

        # TLS
        self.assertEqual(program_headers[7].header_type, "TLS")
        self.assertEqual(program_headers[7].offset, 0xfd84)
        self.assertEqual(program_headers[7].vaddr, 0x1fd84)
        self.assertEqual(program_headers[7].paddr, 0x1fd84)
        self.assertEqual(program_headers[7].filesz, 0x4)
        self.assertEqual(program_headers[7].memsz, 0x8)
        self.assertEqual(program_headers[7].flags, "R")
        self.assertEqual(program_headers[7].align, 0x4)
        self.assertEqual(program_headers[7].reference_file, d.binary.absolute_path)

        # GNU_EH_FRAME
        self.assertEqual(program_headers[8].header_type, "GNU_EH_FRAME")
        self.assertEqual(program_headers[8].offset, 0xc38)
        self.assertEqual(program_headers[8].vaddr, 0xc38)
        self.assertEqual(program_headers[8].paddr, 0xc38)
        self.assertEqual(program_headers[8].filesz, 0x64)
        self.assertEqual(program_headers[8].memsz, 0x64)
        self.assertEqual(program_headers[8].flags, "R")
        self.assertEqual(program_headers[8].align, 0x4)
        self.assertEqual(program_headers[8].reference_file, d.binary.absolute_path)

        # GNU_STACK
        self.assertEqual(program_headers[9].header_type, "GNU_STACK")
        self.assertEqual(program_headers[9].offset, 0x0)
        self.assertEqual(program_headers[9].vaddr, 0x0)
        self.assertEqual(program_headers[9].paddr, 0x0)
        self.assertEqual(program_headers[9].filesz, 0x0)
        self.assertEqual(program_headers[9].memsz, 0x0)
        self.assertEqual(program_headers[9].flags, "RW")
        self.assertEqual(program_headers[9].align, 0x10)
        self.assertEqual(program_headers[9].reference_file, d.binary.absolute_path)

        # GNU_RELRO
        self.assertEqual(program_headers[10].header_type, "GNU_RELRO")
        self.assertEqual(program_headers[10].offset, 0xfd84)
        self.assertEqual(program_headers[10].vaddr, 0x1fd84)
        self.assertEqual(program_headers[10].paddr, 0x1fd84)
        self.assertEqual(program_headers[10].filesz, 0x27c)
        self.assertEqual(program_headers[10].memsz, 0x27c)
        self.assertEqual(program_headers[10].flags, "R")
        self.assertEqual(program_headers[10].align, 0x1)
        self.assertEqual(program_headers[10].reference_file, d.binary.absolute_path)

        d.terminate()

    def test_gnu_properties_aarch64(self):
        """Tests the GNU properties API for aarch64."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "aarch64"), aslr=False)

        gnu_properties = d.binary.gnu_properties

        self.assertEqual(len(gnu_properties), 0)

        d.terminate()

    def test_sections_i386(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "i386"), aslr=False)

        sections = d.binary.sections

        self.assertEqual(len(sections), 35)

        # NULL
        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type, "NULL")

        # .interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x1b4)
        self.assertEqual(sections[1].address, 0x1b4)
        self.assertEqual(sections[1].size, 0x13)
        self.assertEqual(sections[1].flags, "A")
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type, "PROGBITS")

        # .note.gnu.build-id
        self.assertEqual(sections[2].name, ".note.gnu.build-id")
        self.assertEqual(sections[2].offset, 0x1c8)
        self.assertEqual(sections[2].address, 0x1c8)
        self.assertEqual(sections[2].size, 0x24)
        self.assertEqual(sections[2].flags, "A")
        self.assertEqual(sections[2].address_align, 0x4)
        self.assertEqual(sections[2].section_type, "NOTE")

        # .note.ABI-tag
        self.assertEqual(sections[3].name, ".note.ABI-tag")
        self.assertEqual(sections[3].offset, 0x1ec)
        self.assertEqual(sections[3].address, 0x1ec)
        self.assertEqual(sections[3].size, 0x20)
        self.assertEqual(sections[3].flags, "A")
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type, "NOTE")

        # .note.weird
        self.assertEqual(sections[4].name, ".note.weird")
        self.assertEqual(sections[4].offset, 0x20c)
        self.assertEqual(sections[4].address, 0x20c)
        self.assertEqual(sections[4].size, 0x16)
        self.assertEqual(sections[4].flags, "A")
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type, "NOTE")

        # .gnu.hash
        self.assertEqual(sections[5].name, ".gnu.hash")
        self.assertEqual(sections[5].offset, 0x224)
        self.assertEqual(sections[5].address, 0x224)
        self.assertEqual(sections[5].size, 0x20)
        self.assertEqual(sections[5].flags, "A")
        self.assertEqual(sections[5].address_align, 0x4)
        self.assertEqual(sections[5].section_type, "GNU_HASH")

        # .dynsym
        self.assertEqual(sections[6].name, ".dynsym")
        self.assertEqual(sections[6].offset, 0x244)
        self.assertEqual(sections[6].address, 0x244)
        self.assertEqual(sections[6].size, 0xC0)
        self.assertEqual(sections[6].flags, "A")
        self.assertEqual(sections[6].address_align, 0x4)
        self.assertEqual(sections[6].section_type, "DYNSYM")

        # .dynstr
        self.assertEqual(sections[7].name, ".dynstr")
        self.assertEqual(sections[7].offset, 0x304)
        self.assertEqual(sections[7].address, 0x304)
        self.assertEqual(sections[7].size, 0xFE)
        self.assertEqual(sections[7].flags, "A")
        self.assertEqual(sections[7].address_align, 0x1)
        self.assertEqual(sections[7].section_type, "STRTAB")

        # .gnu.version
        self.assertEqual(sections[8].name, ".gnu.version")
        self.assertEqual(sections[8].offset, 0x402)
        self.assertEqual(sections[8].address, 0x402)
        self.assertEqual(sections[8].size, 0x18)
        self.assertEqual(sections[8].flags, "A")
        self.assertEqual(sections[8].address_align, 0x2)
        self.assertEqual(sections[8].section_type, "GNU_VERSYM")

        # .gnu.version_r
        self.assertEqual(sections[9].name, ".gnu.version_r")
        self.assertEqual(sections[9].offset, 0x41C)
        self.assertEqual(sections[9].address, 0x41C)
        self.assertEqual(sections[9].size, 0x70)
        self.assertEqual(sections[9].flags, "A")
        self.assertEqual(sections[9].address_align, 0x4)
        self.assertEqual(sections[9].section_type, "GNU_VERNEED")

        # .rel.dyn
        self.assertEqual(sections[10].name, ".rel.dyn")
        self.assertEqual(sections[10].offset, 0x48C)
        self.assertEqual(sections[10].address, 0x48C)
        self.assertEqual(sections[10].size, 0x68)
        self.assertEqual(sections[10].flags, "A")
        self.assertEqual(sections[10].address_align, 0x4)
        self.assertEqual(sections[10].section_type, "REL")

        # .rel.plt
        self.assertEqual(sections[11].name, ".rel.plt")
        self.assertEqual(sections[11].offset, 0x4F4)
        self.assertEqual(sections[11].address, 0x4F4)
        self.assertEqual(sections[11].size, 0x28)
        self.assertEqual(sections[11].flags, "AI")
        self.assertEqual(sections[11].address_align, 0x4)
        self.assertEqual(sections[11].section_type, "REL")

        # .init
        self.assertEqual(sections[12].name, ".init")
        self.assertEqual(sections[12].offset, 0x1000)
        self.assertEqual(sections[12].address, 0x1000)
        self.assertEqual(sections[12].size, 0x20)
        self.assertEqual(sections[12].flags, "AX")
        self.assertEqual(sections[12].address_align, 0x4)
        self.assertEqual(sections[12].section_type, "PROGBITS")

        # .plt
        self.assertEqual(sections[13].name, ".plt")
        self.assertEqual(sections[13].offset, 0x1020)
        self.assertEqual(sections[13].address, 0x1020)
        self.assertEqual(sections[13].size, 0x60)
        self.assertEqual(sections[13].flags, "AX")
        self.assertEqual(sections[13].address_align, 0x10)
        self.assertEqual(sections[13].section_type, "PROGBITS")

        # .plt.got
        self.assertEqual(sections[14].name, ".plt.got")
        self.assertEqual(sections[14].offset, 0x1080)
        self.assertEqual(sections[14].address, 0x1080)
        self.assertEqual(sections[14].size, 0x8)
        self.assertEqual(sections[14].flags, "AX")
        self.assertEqual(sections[14].address_align, 0x8)
        self.assertEqual(sections[14].section_type, "PROGBITS")

        # .text
        self.assertEqual(sections[15].name, ".text")
        self.assertEqual(sections[15].offset, 0x1090)
        self.assertEqual(sections[15].address, 0x1090)
        self.assertEqual(sections[15].size, 0x2DA)
        self.assertEqual(sections[15].flags, "AX")
        self.assertEqual(sections[15].address_align, 0x10)
        self.assertEqual(sections[15].section_type, "PROGBITS")

        # .fini
        self.assertEqual(sections[16].name, ".fini")
        self.assertEqual(sections[16].offset, 0x136C)
        self.assertEqual(sections[16].address, 0x136C)
        self.assertEqual(sections[16].size, 0x14)
        self.assertEqual(sections[16].flags, "AX")
        self.assertEqual(sections[16].address_align, 0x4)
        self.assertEqual(sections[16].section_type, "PROGBITS")

        # .rodata
        self.assertEqual(sections[17].name, ".rodata")
        self.assertEqual(sections[17].offset, 0x2000)
        self.assertEqual(sections[17].address, 0x2000)
        self.assertEqual(sections[17].size, 0x9A)
        self.assertEqual(sections[17].flags, "A")
        self.assertEqual(sections[17].address_align, 0x4)
        self.assertEqual(sections[17].section_type, "PROGBITS")

        # .eh_frame_hdr
        self.assertEqual(sections[18].name, ".eh_frame_hdr")
        self.assertEqual(sections[18].offset, 0x209C)
        self.assertEqual(sections[18].address, 0x209C)
        self.assertEqual(sections[18].size, 0x5C)
        self.assertEqual(sections[18].flags, "A")
        self.assertEqual(sections[18].address_align, 0x4)
        self.assertEqual(sections[18].section_type, "PROGBITS")

        # .eh_frame
        self.assertEqual(sections[19].name, ".eh_frame")
        self.assertEqual(sections[19].offset, 0x20F8)
        self.assertEqual(sections[19].address, 0x20F8)
        self.assertEqual(sections[19].size, 0x1A0)
        self.assertEqual(sections[19].flags, "A")
        self.assertEqual(sections[19].address_align, 0x4)
        self.assertEqual(sections[19].section_type, "PROGBITS")

        # .tdata
        self.assertEqual(sections[20].name, ".tdata")
        self.assertEqual(sections[20].offset, 0x2EAC)
        self.assertEqual(sections[20].address, 0x3EAC)
        self.assertEqual(sections[20].size, 0x4)
        self.assertEqual(sections[20].flags, "WAT")
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type, "PROGBITS")

        # .tbss
        self.assertEqual(sections[21].name, ".tbss")
        self.assertEqual(sections[21].offset, 0x2EB0)
        self.assertEqual(sections[21].address, 0x3EB0)
        self.assertEqual(sections[21].size, 0x4)
        self.assertEqual(sections[21].flags, "WAT")
        self.assertEqual(sections[21].address_align, 0x4)
        self.assertEqual(sections[21].section_type, "NOBITS")

        # .init_array
        self.assertEqual(sections[22].name, ".init_array")
        self.assertEqual(sections[22].offset, 0x2EB0)
        self.assertEqual(sections[22].address, 0x3EB0)
        self.assertEqual(sections[22].size, 0x8)
        self.assertEqual(sections[22].flags, "WA")
        self.assertEqual(sections[22].address_align, 0x4)
        self.assertEqual(sections[22].section_type, "INIT_ARRAY")

        # .fini_array
        self.assertEqual(sections[23].name, ".fini_array")
        self.assertEqual(sections[23].offset, 0x2EB8)
        self.assertEqual(sections[23].address, 0x3EB8)
        self.assertEqual(sections[23].size, 0x8)
        self.assertEqual(sections[23].flags, "WA")
        self.assertEqual(sections[23].address_align, 0x4)
        self.assertEqual(sections[23].section_type, "FINI_ARRAY")

        # .data.rel.ro
        self.assertEqual(sections[24].name, ".data.rel.ro")
        self.assertEqual(sections[24].offset, 0x2EC0)
        self.assertEqual(sections[24].address, 0x3EC0)
        self.assertEqual(sections[24].size, 0x4)
        self.assertEqual(sections[24].flags, "WA")
        self.assertEqual(sections[24].address_align, 0x4)
        self.assertEqual(sections[24].section_type, "PROGBITS")

        # .dynamic
        self.assertEqual(sections[25].name, ".dynamic")
        self.assertEqual(sections[25].offset, 0x2EC4)
        self.assertEqual(sections[25].address, 0x3EC4)
        self.assertEqual(sections[25].size, 0x100)
        self.assertEqual(sections[25].flags, "WA")
        self.assertEqual(sections[25].address_align, 0x4)
        self.assertEqual(sections[25].section_type, "DYNAMIC")

        # .got
        self.assertEqual(sections[26].name, ".got")
        self.assertEqual(sections[26].offset, 0x2FC4)
        self.assertEqual(sections[26].address, 0x3FC4)
        self.assertEqual(sections[26].size, 0x3C)
        self.assertEqual(sections[26].flags, "WA")
        self.assertEqual(sections[26].address_align, 0x4)
        self.assertEqual(sections[26].section_type, "PROGBITS")

        # .data
        self.assertEqual(sections[27].name, ".data")
        self.assertEqual(sections[27].offset, 0x3000)
        self.assertEqual(sections[27].address, 0x4000)
        self.assertEqual(sections[27].size, 0xA0)
        self.assertEqual(sections[27].flags, "WA")
        self.assertEqual(sections[27].address_align, 0x40)
        self.assertEqual(sections[27].section_type, "PROGBITS")

        # .extra.data
        self.assertEqual(sections[28].name, ".extra.data")
        self.assertEqual(sections[28].offset, 0x30A0)
        self.assertEqual(sections[28].address, 0x40A0)
        self.assertEqual(sections[28].size, 0x8)
        self.assertEqual(sections[28].flags, "WA")
        self.assertEqual(sections[28].address_align, 0x10)
        self.assertEqual(sections[28].section_type, "PROGBITS")

        # .bss
        self.assertEqual(sections[29].name, ".bss")
        self.assertEqual(sections[29].offset, 0x30A8)
        self.assertEqual(sections[29].address, 0x40C0)
        self.assertEqual(sections[29].size, 0x1140)
        self.assertEqual(sections[29].flags, "WA")
        self.assertEqual(sections[29].address_align, 0x20)
        self.assertEqual(sections[29].section_type, "NOBITS")

        # .comment
        self.assertEqual(sections[30].name, ".comment")
        self.assertEqual(sections[30].offset, 0x30A8)
        self.assertEqual(sections[30].address, 0x0)
        self.assertEqual(sections[30].size, 0x2B)
        self.assertEqual(sections[30].flags, "MS")
        self.assertEqual(sections[30].address_align, 0x1)
        self.assertEqual(sections[30].section_type, "PROGBITS")

        # .weird.debug
        self.assertEqual(sections[31].name, ".weird.debug")
        self.assertEqual(sections[31].offset, 0x30D3)
        self.assertEqual(sections[31].address, 0x0)
        self.assertEqual(sections[31].size, 0x1F)
        self.assertEqual(sections[31].flags, "")
        self.assertEqual(sections[31].address_align, 0x1)
        self.assertEqual(sections[31].section_type, "PROGBITS")

        # .symtab
        self.assertEqual(sections[32].name, ".symtab")
        self.assertEqual(sections[32].offset, 0x30F4)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x410)
        self.assertEqual(sections[32].flags, "")
        self.assertEqual(sections[32].address_align, 0x4)
        self.assertEqual(sections[32].section_type, "SYMTAB")

        # .strtab
        self.assertEqual(sections[33].name, ".strtab")
        self.assertEqual(sections[33].offset, 0x3504)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x3B6)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type, "STRTAB")

        # .shstrtab
        self.assertEqual(sections[34].name, ".shstrtab")
        self.assertEqual(sections[34].offset, 0x38BA)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x135)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x1)
        self.assertEqual(sections[34].section_type, "STRTAB")

        d.terminate()

    def test_dynamic_sections_i386(self):
        """Tests the dynamic sections API for i386."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "i386"), aslr=False)

        dynamic_sections = d.binary.dynamic_sections

        # There should be 12 dynamic sections
        self.assertEqual(len(dynamic_sections), 27)

        # There should be 27 dynamic entries (already asserted above), validate them:
        self.assertEqual(dynamic_sections[0].tag, "NEEDED")
        self.assertEqual(dynamic_sections[0].value, "libc.so.6")
        self.assertFalse(dynamic_sections[0].is_value_address)
        self.assertEqual(dynamic_sections[0].reference_file, d.binary.absolute_path)

        self.assertEqual(dynamic_sections[1].tag, "NEEDED")
        self.assertEqual(dynamic_sections[1].value, "ld-linux.so.2")
        self.assertFalse(dynamic_sections[1].is_value_address)
        self.assertEqual(dynamic_sections[1].reference_file, d.binary.absolute_path)

        self.assertEqual(dynamic_sections[2].tag, "INIT")
        self.assertEqual(dynamic_sections[2].value, 0x1000)
        self.assertTrue(dynamic_sections[2].is_value_address)

        self.assertEqual(dynamic_sections[3].tag, "FINI")
        self.assertEqual(dynamic_sections[3].value, 0x136c)
        self.assertTrue(dynamic_sections[3].is_value_address)

        self.assertEqual(dynamic_sections[4].tag, "INIT_ARRAY")
        self.assertEqual(dynamic_sections[4].value, 0x3eb0)
        self.assertTrue(dynamic_sections[4].is_value_address)

        self.assertEqual(dynamic_sections[5].tag, "INIT_ARRAYSZ")
        self.assertEqual(dynamic_sections[5].value, 8)

        self.assertEqual(dynamic_sections[6].tag, "FINI_ARRAY")
        self.assertEqual(dynamic_sections[6].value, 0x3eb8)
        self.assertTrue(dynamic_sections[6].is_value_address)

        self.assertEqual(dynamic_sections[7].tag, "FINI_ARRAYSZ")
        self.assertEqual(dynamic_sections[7].value, 8)

        self.assertEqual(dynamic_sections[8].tag, "GNU_HASH")
        self.assertEqual(dynamic_sections[8].value, 0x224)
        self.assertTrue(dynamic_sections[8].is_value_address)

        self.assertEqual(dynamic_sections[9].tag, "STRTAB")
        self.assertEqual(dynamic_sections[9].value, 0x304)
        self.assertTrue(dynamic_sections[9].is_value_address)

        self.assertEqual(dynamic_sections[10].tag, "SYMTAB")
        self.assertEqual(dynamic_sections[10].value, 0x244)
        self.assertTrue(dynamic_sections[10].is_value_address)

        self.assertEqual(dynamic_sections[11].tag, "STRSZ")
        self.assertEqual(dynamic_sections[11].value, 254)

        self.assertEqual(dynamic_sections[12].tag, "SYMENT")
        self.assertEqual(dynamic_sections[12].value, 16)

        self.assertEqual(dynamic_sections[13].tag, "DEBUG")
        self.assertEqual(dynamic_sections[13].value, 0x0)

        self.assertEqual(dynamic_sections[14].tag, "PLTGOT")
        self.assertEqual(dynamic_sections[14].value, 0x3fc4)
        self.assertTrue(dynamic_sections[14].is_value_address)

        self.assertEqual(dynamic_sections[15].tag, "PLTRELSZ")
        self.assertEqual(dynamic_sections[15].value, 40)

        self.assertEqual(dynamic_sections[16].tag, "PLTREL")
        self.assertEqual(dynamic_sections[16].value, "REL")

        self.assertEqual(dynamic_sections[17].tag, "JMPREL")
        self.assertEqual(dynamic_sections[17].value, 0x4f4)
        self.assertTrue(dynamic_sections[17].is_value_address)

        self.assertEqual(dynamic_sections[18].tag, "REL")
        self.assertEqual(dynamic_sections[18].value, 0x48c)
        self.assertTrue(dynamic_sections[18].is_value_address)

        self.assertEqual(dynamic_sections[19].tag, "RELSZ")
        self.assertEqual(dynamic_sections[19].value, 104)

        self.assertEqual(dynamic_sections[20].tag, "RELENT")
        self.assertEqual(dynamic_sections[20].value, 8)

        self.assertEqual(dynamic_sections[21].tag, "FLAGS")
        self.assertEqual(dynamic_sections[21].value, "BIND_NOW")

        self.assertEqual(dynamic_sections[22].tag, "FLAGS_1")
        self.assertEqual(dynamic_sections[22].value, "NOW PIE")

        self.assertEqual(dynamic_sections[23].tag, "VERNEED")
        self.assertEqual(dynamic_sections[23].value, 0x41c)
        self.assertTrue(dynamic_sections[23].is_value_address)

        self.assertEqual(dynamic_sections[24].tag, "VERNEEDNUM")
        self.assertEqual(dynamic_sections[24].value, 2)

        self.assertEqual(dynamic_sections[25].tag, "VERSYM")
        self.assertEqual(dynamic_sections[25].value, 0x402)
        self.assertTrue(dynamic_sections[25].is_value_address)

        self.assertEqual(dynamic_sections[26].tag, "RELCOUNT")
        self.assertEqual(dynamic_sections[26].value, 8)

        d.terminate()

    def test_program_headers_i386(self):
        """Tests the program headers API for i386."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE_CROSS("sections_test", "i386"), aslr=False)

        program_headers = d.binary.program_headers
        
        self.assertEqual(len(program_headers), 12)
        # PHDR
        self.assertEqual(program_headers[0].header_type, "PHDR")
        self.assertEqual(program_headers[0].offset, 0x34)
        self.assertEqual(program_headers[0].vaddr, 0x34)
        self.assertEqual(program_headers[0].paddr, 0x34)
        self.assertEqual(program_headers[0].filesz, 0x180)
        self.assertEqual(program_headers[0].memsz, 0x180)
        self.assertEqual(program_headers[0].flags, "R")
        self.assertEqual(program_headers[0].align, 0x4)
        self.assertEqual(program_headers[0].reference_file, d.binary.absolute_path)

        # INTERP
        self.assertEqual(program_headers[1].header_type, "INTERP")
        self.assertEqual(program_headers[1].offset, 0x1b4)
        self.assertEqual(program_headers[1].vaddr, 0x1b4)
        self.assertEqual(program_headers[1].paddr, 0x1b4)
        self.assertEqual(program_headers[1].filesz, 0x13)
        self.assertEqual(program_headers[1].memsz, 0x13)
        self.assertEqual(program_headers[1].flags, "R")
        self.assertEqual(program_headers[1].align, 0x1)
        self.assertEqual(program_headers[1].reference_file, d.binary.absolute_path)

        # LOAD (first)
        self.assertEqual(program_headers[2].header_type, "LOAD")
        self.assertEqual(program_headers[2].offset, 0x0)
        self.assertEqual(program_headers[2].vaddr, 0x0)
        self.assertEqual(program_headers[2].paddr, 0x0)
        self.assertEqual(program_headers[2].filesz, 0x51c)
        self.assertEqual(program_headers[2].memsz, 0x51c)
        self.assertEqual(program_headers[2].flags, "R")
        self.assertEqual(program_headers[2].align, 0x1000)
        self.assertEqual(program_headers[2].reference_file, d.binary.absolute_path)

        # LOAD (second)
        self.assertEqual(program_headers[3].header_type, "LOAD")
        self.assertEqual(program_headers[3].offset, 0x1000)
        self.assertEqual(program_headers[3].vaddr, 0x1000)
        self.assertEqual(program_headers[3].paddr, 0x1000)
        self.assertEqual(program_headers[3].filesz, 0x380)
        self.assertEqual(program_headers[3].memsz, 0x380)
        self.assertEqual(program_headers[3].flags, "RX")
        self.assertEqual(program_headers[3].align, 0x1000)
        self.assertEqual(program_headers[3].reference_file, d.binary.absolute_path)

        # LOAD (third)
        self.assertEqual(program_headers[4].header_type, "LOAD")
        self.assertEqual(program_headers[4].offset, 0x2000)
        self.assertEqual(program_headers[4].vaddr, 0x2000)
        self.assertEqual(program_headers[4].paddr, 0x2000)
        self.assertEqual(program_headers[4].filesz, 0x298)
        self.assertEqual(program_headers[4].memsz, 0x298)
        self.assertEqual(program_headers[4].flags, "R")
        self.assertEqual(program_headers[4].align, 0x1000)
        self.assertEqual(program_headers[4].reference_file, d.binary.absolute_path)

        # LOAD (fourth)
        self.assertEqual(program_headers[5].header_type, "LOAD")
        self.assertEqual(program_headers[5].offset, 0x2eac)
        self.assertEqual(program_headers[5].vaddr, 0x3eac)
        self.assertEqual(program_headers[5].paddr, 0x3eac)
        self.assertEqual(program_headers[5].filesz, 0x1fc)
        self.assertEqual(program_headers[5].memsz, 0x1354)
        self.assertEqual(program_headers[5].flags, "RW")
        self.assertEqual(program_headers[5].align, 0x1000)
        self.assertEqual(program_headers[5].reference_file, d.binary.absolute_path)

        # DYNAMIC
        self.assertEqual(program_headers[6].header_type, "DYNAMIC")
        self.assertEqual(program_headers[6].offset, 0x2ec4)
        self.assertEqual(program_headers[6].vaddr, 0x3ec4)
        self.assertEqual(program_headers[6].paddr, 0x3ec4)
        self.assertEqual(program_headers[6].filesz, 0x100)
        self.assertEqual(program_headers[6].memsz, 0x100)
        self.assertEqual(program_headers[6].flags, "RW")
        self.assertEqual(program_headers[6].align, 0x4)
        self.assertEqual(program_headers[6].reference_file, d.binary.absolute_path)

        # NOTE
        self.assertEqual(program_headers[7].header_type, "NOTE")
        self.assertEqual(program_headers[7].offset, 0x1c8)
        self.assertEqual(program_headers[7].vaddr, 0x1c8)
        self.assertEqual(program_headers[7].paddr, 0x1c8)
        self.assertEqual(program_headers[7].filesz, 0x5a)
        self.assertEqual(program_headers[7].memsz, 0x5a)
        self.assertEqual(program_headers[7].flags, "R")
        self.assertEqual(program_headers[7].align, 0x4)
        self.assertEqual(program_headers[7].reference_file, d.binary.absolute_path)

        # TLS
        self.assertEqual(program_headers[8].header_type, "TLS")
        self.assertEqual(program_headers[8].offset, 0x2eac)
        self.assertEqual(program_headers[8].vaddr, 0x3eac)
        self.assertEqual(program_headers[8].paddr, 0x3eac)
        self.assertEqual(program_headers[8].filesz, 0x4)
        self.assertEqual(program_headers[8].memsz, 0x8)
        self.assertEqual(program_headers[8].flags, "R")
        self.assertEqual(program_headers[8].align, 0x4)
        self.assertEqual(program_headers[8].reference_file, d.binary.absolute_path)

        # GNU_EH_FRAME
        self.assertEqual(program_headers[9].header_type, "GNU_EH_FRAME")
        self.assertEqual(program_headers[9].offset, 0x209c)
        self.assertEqual(program_headers[9].vaddr, 0x209c)
        self.assertEqual(program_headers[9].paddr, 0x209c)
        self.assertEqual(program_headers[9].filesz, 0x5c)
        self.assertEqual(program_headers[9].memsz, 0x5c)
        self.assertEqual(program_headers[9].flags, "R")
        self.assertEqual(program_headers[9].align, 0x4)
        self.assertEqual(program_headers[9].reference_file, d.binary.absolute_path)

        # GNU_STACK
        self.assertEqual(program_headers[10].header_type, "GNU_STACK")
        self.assertEqual(program_headers[10].offset, 0x0)
        self.assertEqual(program_headers[10].vaddr, 0x0)
        self.assertEqual(program_headers[10].paddr, 0x0)
        self.assertEqual(program_headers[10].filesz, 0x0)
        self.assertEqual(program_headers[10].memsz, 0x0)
        self.assertEqual(program_headers[10].flags, "RW")
        self.assertEqual(program_headers[10].align, 0x10)
        self.assertEqual(program_headers[10].reference_file, d.binary.absolute_path)

        # GNU_RELRO
        self.assertEqual(program_headers[11].header_type, "GNU_RELRO")
        self.assertEqual(program_headers[11].offset, 0x2eac)
        self.assertEqual(program_headers[11].vaddr, 0x3eac)
        self.assertEqual(program_headers[11].paddr, 0x3eac)
        self.assertEqual(program_headers[11].filesz, 0x154)
        self.assertEqual(program_headers[11].memsz, 0x154)
        self.assertEqual(program_headers[11].flags, "R")
        self.assertEqual(program_headers[11].align, 0x1)
        self.assertEqual(program_headers[11].reference_file, d.binary.absolute_path)

        d.terminate()


    def test_binary_and_libs_api(self):
        """Tests the binary and libraries API."""
        rel_path = RESOLVE_EXE("sections_test")

        # Create a debugger and start execution
        d = debugger(rel_path, aslr=False)

        ENTRY_POINTS = {
            "i386": 0x1180,
            "aarch64": 0x940,
            "amd64": 0x1190,
        }

        self.assertEqual(d.binary.path.split("/")[-1], "sections_test")
        self.assertEqual(d.binary.absolute_path, str(Path(rel_path).resolve()))
        self.assertEqual(d.binary.architecture, PLATFORM)
        self.assertEqual(d.binary.is_pie, True)
        self.assertEqual(d.binary.entry_point, ENTRY_POINTS[PLATFORM])
        self.assertEqual(d.binary.endianness, "little")

        match PLATFORM:
            case "i386":
                gt_build_id = "3ffb142e23aeef6017d9cae1e90da130dae0a697"
            case "aarch64":
                gt_build_id = "93beda343351604e97878bbb8605dc4a13644d76"
            case "amd64":
                gt_build_id = "de1a4f0ca53a82f9590cc4a3cfaaec5fe86aabaf"
            case _:
                self.fail(f"Unsupported platform: {PLATFORM}")

        self.assertEqual(d.binary.build_id, gt_build_id)

        self.assertRaises(ValueError, lambda: d.binary.symbols)
        self.assertRaises(RuntimeError, lambda: d.libraries)
        self.assertRaises(RuntimeError, lambda: d.libs)

        d.run()

        self.assertEqual(d.binary.base_address, BASE)

        match PLATFORM:
            case "i386":
                num_symbols = 50
            case "aarch64":
                num_symbols = 117
            case "amd64":
                num_symbols = 46
            case _:
                self.fail(f"Unsupported platform: {PLATFORM}")

        self.assertEqual(len(d.binary.symbols), num_symbols)

        self.assertEqual(len(d.libraries), 2)

        match PLATFORM:
            case "i386":
                self.assertEqual("libc.so.6", d.libraries[0].soname)
                self.assertEqual("ld-linux.so.2", d.libraries[1].soname)
            case "aarch64":
                self.assertEqual("libc.so.6", d.libraries[0].soname)
                self.assertEqual("ld-linux-aarch64.so.1", d.libraries[1].soname)
            case "amd64":
                self.assertEqual("libc.so.6", d.libraries[0].soname)
                self.assertEqual("ld-linux-x86-64.so.2", d.libraries[1].soname)
            case _:
                self.fail(f"Unsupported platform: {PLATFORM}")
 
        d.terminate()

    def test_dlopen_libs_api(self):
        path = RESOLVE_EXE("dynamic_lib_load")
        d = debugger(path, aslr=False)
        d.run()

        self.assertEqual(len(d.libs), 2)

        # Sort libs by soname for consistency
        libs = sorted(d.libs, key=lambda lib: lib.soname)

        match PLATFORM:
            case "i386":
                self.assertEqual(libs[0].soname, "ld-linux.so.2")
            case "aarch64":
                self.assertEqual(libs[0].soname, "ld-linux-aarch64.so.1")
            case "amd64":
                self.assertEqual(libs[0].soname, "ld-linux-x86-64.so.2")
            case _:
                raise ValueError(f"Unsupported platform: {PLATFORM}")
            
        self.assertEqual(libs[1].soname, "libc.so.6")

        d.terminate()

        d = debugger(path, aslr=False)
        d.run()

        match PLATFORM:
            case "i386":
                bp_address = 0x12da
            case "aarch64":
                bp_address = 0xa38
            case "amd64":
                bp_address = 0x12a5

        # When breakpoint is reached, the binary will already have called dlopen
        bp = d.breakpoint(bp_address, hardware=True, file="binary")

        d.cont()

        self.assertEqual(bp.hit_on(d), True)

        # Recheck the libs
        self.assertEqual(len(d.libs), 3)

        # Sort libs by soname for consistency
        libs = sorted(d.libs, key=lambda lib: lib.soname)

        match PLATFORM:
            case "i386":
                self.assertEqual(libs[0].soname, "ld-linux.so.2")
            case "aarch64":
                self.assertEqual(libs[0].soname, "ld-linux-aarch64.so.1")
            case "amd64":
                self.assertEqual(libs[0].soname, "ld-linux-x86-64.so.2")
            case _:
                raise ValueError(f"Unsupported platform: {PLATFORM}")

        self.assertEqual(libs[1].soname, "libc.so.6")
        self.assertEqual(libs[2].soname, "libm.so.6")

        d.terminate()


    def test_binary_mitigations(self):
        """Tests the binary mitigations API."""
        # AMD64 mitigationsv1
        rel_path = RESOLVE_EXE_CROSS("mitigationsv1", "amd64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.FULL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertTrue(mitigations.shstk)
        self.assertTrue(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # AMD64 mitigationsv2
        rel_path = RESOLVE_EXE_CROSS("mitigationsv2", "amd64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.PARTIAL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertFalse(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # AMD64 mitigationsv3
        rel_path = RESOLVE_EXE_CROSS("mitigationsv3", "amd64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.NONE)
        self.assertFalse(mitigations.stack_guard)
        self.assertEqual(mitigations.nx, None) # Depends on READ_IMPLIES_EXEC
        self.assertTrue(mitigations.stack_executable)
        self.assertFalse(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertFalse(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # AMD64 mitigationsv4
        rel_path = RESOLVE_EXE_CROSS("mitigationsv4", "amd64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.FULL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertTrue(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # -------------------------

        # i386 mitigationsv1
        rel_path = RESOLVE_EXE_CROSS("mitigationsv1", "i386")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.FULL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # i386 mitigationsv2
        rel_path = RESOLVE_EXE_CROSS("mitigationsv2", "i386")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.PARTIAL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertFalse(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # i386 mitigationsv3
        rel_path = RESOLVE_EXE_CROSS("mitigationsv3", "i386")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.NONE)
        self.assertFalse(mitigations.stack_guard)
        self.assertEqual(mitigations.nx, None) # Depends on READ_IMPLIES_EXEC
        self.assertTrue(mitigations.stack_executable)
        self.assertFalse(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertFalse(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # -------------------------

        # AArch64 mitigationsv1
        rel_path = RESOLVE_EXE_CROSS("mitigationsv1", "aarch64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.FULL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)

        # AArch64 GCS support is recent and still shaky, using a compiled GLIBC with GCS for the test
        rel_path = RESOLVE_EXE_CROSS("glibc-2.42-mitigations-gcs.so", "aarch64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.PARTIAL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertTrue(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertTrue(mitigations.pac)

        # AArch64 mitigationsv3
        rel_path = RESOLVE_EXE_CROSS("mitigationsv3", "aarch64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.FULL)
        self.assertTrue(mitigations.stack_guard)
        self.assertTrue(mitigations.nx)
        self.assertFalse(mitigations.stack_executable)
        self.assertTrue(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertTrue(mitigations.ibt)
        self.assertTrue(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertTrue(mitigations.pac)

        # AArch64 mitigationsv4
        rel_path = RESOLVE_EXE_CROSS("mitigationsv4", "aarch64")
        d = debugger(rel_path, aslr=False)
        mitigations = d.binary.runtime_mitigations

        self.assertEqual(mitigations.relro, RelroStatus.NONE)
        self.assertFalse(mitigations.stack_guard)
        self.assertEqual(mitigations.nx, None) # Depends on READ_IMPLIES_EXEC
        self.assertTrue(mitigations.stack_executable)
        self.assertFalse(mitigations.pie)
        self.assertFalse(mitigations.shstk)
        self.assertFalse(mitigations.ibt)
        self.assertFalse(mitigations.fortify)
        self.assertFalse(mitigations.asan)
        self.assertFalse(mitigations.msan)
        self.assertFalse(mitigations.ubsan)
        self.assertFalse(mitigations.pac)
