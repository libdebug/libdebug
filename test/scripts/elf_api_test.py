#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase, skipUnless
from utils.binary_utils import RESOLVE_EXE
from libdebug import debugger

from utils.binary_utils import PLATFORM, BASE


class ElfApiTest(TestCase):

    @skipUnless(PLATFORM == "amd64", "Requires amd64")
    def test_sections_amd64(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("sections_test"), aslr=False)
        d.run()

        sections = d.binary.sections

        self.assertEqual(len(sections), 37)

        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type.name, "SHT_NULL")

        #.interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x350)
        self.assertEqual(sections[1].address, 0x350)
        self.assertEqual(sections[1].size, 0x1c)
        self.assertEqual(sections[1].flags, "A")  # ALLOC
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type.name, "SHT_PROGBITS")

        #.note.gnu.property
        self.assertEqual(sections[2].name, ".note.gnu.property")
        self.assertEqual(sections[2].offset, 0x370)
        self.assertEqual(sections[2].address, 0x370)
        self.assertEqual(sections[2].size, 0x30)
        self.assertEqual(sections[2].flags, "A")  # ALLOC
        self.assertEqual(sections[2].address_align, 0x8)
        self.assertEqual(sections[2].section_type.name, "SHT_NOTE")

        #.note.gnu.build-id
        self.assertEqual(sections[3].name, ".note.gnu.build-id")
        self.assertEqual(sections[3].offset, 0x3a0)
        self.assertEqual(sections[3].address, 0x3a0)
        self.assertEqual(sections[3].size, 0x24)
        self.assertEqual(sections[3].flags, "A")  # ALLOC
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type.name, "SHT_NOTE")

        #.note.ABI-tag
        self.assertEqual(sections[4].name, ".note.ABI-tag")
        self.assertEqual(sections[4].offset, 0x3c4)
        self.assertEqual(sections[4].address, 0x3c4)
        self.assertEqual(sections[4].size, 0x20)
        self.assertEqual(sections[4].flags, "A")  # ALLOC
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type.name, "SHT_NOTE")

        #.note.weird
        self.assertEqual(sections[5].name, ".note.weird")
        self.assertEqual(sections[5].offset, 0x3e4)
        self.assertEqual(sections[5].address, 0x3e4)
        self.assertEqual(sections[5].size, 0x16)
        self.assertEqual(sections[5].flags, "A")  # ALLOC
        self.assertEqual(sections[5].address_align, 0x4)
        self.assertEqual(sections[5].section_type.name, "SHT_NOTE")

        #.gnu.hash
        self.assertEqual(sections[6].name, ".gnu.hash")
        self.assertEqual(sections[6].offset, 0x400)
        self.assertEqual(sections[6].address, 0x400)
        self.assertEqual(sections[6].size, 0x24)
        self.assertEqual(sections[6].flags, "A")  # ALLOC
        self.assertEqual(sections[6].address_align, 0x8)
        self.assertEqual(sections[6].section_type.name, "SHT_GNU_HASH")

        #.dynsym
        self.assertEqual(sections[7].name, ".dynsym")
        self.assertEqual(sections[7].offset, 0x428)
        self.assertEqual(sections[7].address, 0x428)
        self.assertEqual(sections[7].size, 0x108)
        self.assertEqual(sections[7].flags, "A")  # ALLOC
        self.assertEqual(sections[7].address_align, 0x8)
        self.assertEqual(sections[7].section_type.name, "SHT_DYNSYM")

        #.dynstr
        self.assertEqual(sections[8].name, ".dynstr")
        self.assertEqual(sections[8].offset, 0x530)
        self.assertEqual(sections[8].address, 0x530)
        self.assertEqual(sections[8].size, 0xeb)
        self.assertEqual(sections[8].flags, "A")  # ALLOC
        self.assertEqual(sections[8].address_align, 0x1)
        self.assertEqual(sections[8].section_type.name, "SHT_STRTAB")

        #.gnu.version
        self.assertEqual(sections[9].name, ".gnu.version")
        self.assertEqual(sections[9].offset, 0x61c)
        self.assertEqual(sections[9].address, 0x61c)
        self.assertEqual(sections[9].size, 0x16)
        self.assertEqual(sections[9].flags, "A")  # ALLOC
        self.assertEqual(sections[9].address_align, 0x2)
        self.assertEqual(sections[9].section_type.name, "SHT_GNU_VERSYM")

        #.gnu.version_r
        self.assertEqual(sections[10].name, ".gnu.version_r")
        self.assertEqual(sections[10].offset, 0x638)
        self.assertEqual(sections[10].address, 0x638)
        self.assertEqual(sections[10].size, 0x60)
        self.assertEqual(sections[10].flags, "A")  # ALLOC
        self.assertEqual(sections[10].address_align, 0x8)
        self.assertEqual(sections[10].section_type.name, "SHT_GNU_VERNEED")

        #.rela.dyn
        self.assertEqual(sections[11].name, ".rela.dyn")
        self.assertEqual(sections[11].offset, 0x698)
        self.assertEqual(sections[11].address, 0x698)
        self.assertEqual(sections[11].size, 0x138)
        self.assertEqual(sections[11].flags, "A")  # ALLOC
        self.assertEqual(sections[11].address_align, 0x8)
        self.assertEqual(sections[11].section_type.name, "SHT_RELA")

        #.rela.plt
        self.assertEqual(sections[12].name, ".rela.plt")
        self.assertEqual(sections[12].offset, 0x7d0)
        self.assertEqual(sections[12].address, 0x7d0)
        self.assertEqual(sections[12].size, 0x60)
        self.assertEqual(sections[12].flags, "AI")  # ALLOC INFOLINK
        self.assertEqual(sections[12].address_align, 0x8)
        self.assertEqual(sections[12].section_type.name, "SHT_RELA")

        #.init
        self.assertEqual(sections[13].name, ".init")
        self.assertEqual(sections[13].offset, 0x1000)
        self.assertEqual(sections[13].address, 0x1000)
        self.assertEqual(sections[13].size, 0x1b)
        self.assertEqual(sections[13].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[13].address_align, 0x4)
        self.assertEqual(sections[13].section_type.name, "SHT_PROGBITS")

        #.plt
        self.assertEqual(sections[14].name, ".plt")
        self.assertEqual(sections[14].offset, 0x1020)
        self.assertEqual(sections[14].address, 0x1020)
        self.assertEqual(sections[14].size, 0x50)
        self.assertEqual(sections[14].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[14].address_align, 0x10)
        self.assertEqual(sections[14].section_type.name, "SHT_PROGBITS")

        #.plt.got
        self.assertEqual(sections[15].name, ".plt.got")
        self.assertEqual(sections[15].offset, 0x1070)
        self.assertEqual(sections[15].address, 0x1070)
        self.assertEqual(sections[15].size, 0x10)
        self.assertEqual(sections[15].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[15].address_align, 0x10)
        self.assertEqual(sections[15].section_type.name, "SHT_PROGBITS")

        #.plt.sec
        self.assertEqual(sections[16].name, ".plt.sec")
        self.assertEqual(sections[16].offset, 0x1080)
        self.assertEqual(sections[16].address, 0x1080)
        self.assertEqual(sections[16].size, 0x40)
        self.assertEqual(sections[16].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[16].address_align, 0x10)
        self.assertEqual(sections[16].section_type.name, "SHT_PROGBITS")

        #.text
        self.assertEqual(sections[17].name, ".text")
        self.assertEqual(sections[17].offset, 0x10c0)
        self.assertEqual(sections[17].address, 0x10c0)
        self.assertEqual(sections[17].size, 0x27a)
        self.assertEqual(sections[17].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[17].address_align, 0x10)
        self.assertEqual(sections[17].section_type.name, "SHT_PROGBITS")

        #.fini
        self.assertEqual(sections[18].name, ".fini")
        self.assertEqual(sections[18].offset, 0x133c)
        self.assertEqual(sections[18].address, 0x133c)
        self.assertEqual(sections[18].size, 0xd)
        self.assertEqual(sections[18].flags, "AX")  # ALLOC EXEC
        self.assertEqual(sections[18].address_align, 0x4)
        self.assertEqual(sections[18].section_type.name, "SHT_PROGBITS")

        #.rodata
        self.assertEqual(sections[19].name, ".rodata")
        self.assertEqual(sections[19].offset, 0x2000)
        self.assertEqual(sections[19].address, 0x2000)
        self.assertEqual(sections[19].size, 0x96)
        self.assertEqual(sections[19].flags, "A")  # ALLOC
        self.assertEqual(sections[19].address_align, 0x8)
        self.assertEqual(sections[19].section_type.name, "SHT_PROGBITS")

        #.eh_frame_hdr
        self.assertEqual(sections[20].name, ".eh_frame_hdr")
        self.assertEqual(sections[20].offset, 0x2098)
        self.assertEqual(sections[20].address, 0x2098)
        self.assertEqual(sections[20].size, 0x64)
        self.assertEqual(sections[20].flags, "A")  # ALLOC
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type.name, "SHT_PROGBITS")

        #.eh_frame
        self.assertEqual(sections[21].name, ".eh_frame")
        self.assertEqual(sections[21].offset, 0x2100)
        self.assertEqual(sections[21].address, 0x2100)
        self.assertEqual(sections[21].size, 0x138)
        self.assertEqual(sections[21].flags, "A")  # ALLOC
        self.assertEqual(sections[21].address_align, 0x8)
        self.assertEqual(sections[21].section_type.name, "SHT_PROGBITS")

        #.tdata
        self.assertEqual(sections[22].name, ".tdata")
        self.assertEqual(sections[22].offset, 0x2d64)
        self.assertEqual(sections[22].address, 0x3d64)
        self.assertEqual(sections[22].size, 0x4)
        self.assertEqual(sections[22].flags, "WAT")  # WRITABLE ALLOC TLS
        self.assertEqual(sections[22].address_align, 0x4)
        self.assertEqual(sections[22].section_type.name, "SHT_PROGBITS")

        #.tbss
        self.assertEqual(sections[23].name, ".tbss")
        self.assertEqual(sections[23].offset, 0x2d68)
        self.assertEqual(sections[23].address, 0x3d68)
        self.assertEqual(sections[23].size, 0x4)
        self.assertEqual(sections[23].flags, "WAT")  # WRITABLE ALLOC TLS
        self.assertEqual(sections[23].address_align, 0x4)
        self.assertEqual(sections[23].section_type.name, "SHT_NOBITS")

        #.init_array
        self.assertEqual(sections[24].name, ".init_array")
        self.assertEqual(sections[24].offset, 0x2d68)
        self.assertEqual(sections[24].address, 0x3d68)
        self.assertEqual(sections[24].size, 0x10)
        self.assertEqual(sections[24].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[24].address_align, 0x8)
        self.assertEqual(sections[24].section_type.name, "SHT_INIT_ARRAY")

        #.fini_array
        self.assertEqual(sections[25].name, ".fini_array")
        self.assertEqual(sections[25].offset, 0x2d78)
        self.assertEqual(sections[25].address, 0x3d78)
        self.assertEqual(sections[25].size, 0x10)
        self.assertEqual(sections[25].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[25].address_align, 0x8)
        self.assertEqual(sections[25].section_type.name, "SHT_FINI_ARRAY")

        #.data.rel.ro
        self.assertEqual(sections[26].name, ".data.rel.ro")
        self.assertEqual(sections[26].offset, 0x2d88)
        self.assertEqual(sections[26].address, 0x3d88)
        self.assertEqual(sections[26].size, 0x8)
        self.assertEqual(sections[26].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[26].address_align, 0x8)
        self.assertEqual(sections[26].section_type.name, "SHT_PROGBITS")

        #.dynamic
        self.assertEqual(sections[27].name, ".dynamic")
        self.assertEqual(sections[27].offset, 0x2d90)
        self.assertEqual(sections[27].address, 0x3d90)
        self.assertEqual(sections[27].size, 0x200)
        self.assertEqual(sections[27].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[27].address_align, 0x8)
        self.assertEqual(sections[27].section_type.name, "SHT_DYNAMIC")

        #.got
        self.assertEqual(sections[28].name, ".got")
        self.assertEqual(sections[28].offset, 0x2f90)
        self.assertEqual(sections[28].address, 0x3f90)
        self.assertEqual(sections[28].size, 0x70)
        self.assertEqual(sections[28].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[28].address_align, 0x8)
        self.assertEqual(sections[28].section_type.name, "SHT_PROGBITS")

        #.data
        self.assertEqual(sections[29].name, ".data")
        self.assertEqual(sections[29].offset, 0x3000)
        self.assertEqual(sections[29].address, 0x4000)
        self.assertEqual(sections[29].size, 0xa0)
        self.assertEqual(sections[29].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[29].address_align, 0x40)
        self.assertEqual(sections[29].section_type.name, "SHT_PROGBITS")

        #.extra.data
        self.assertEqual(sections[30].name, ".extra.data")
        self.assertEqual(sections[30].offset, 0x30a0)
        self.assertEqual(sections[30].address, 0x40a0)
        self.assertEqual(sections[30].size, 0x8)
        self.assertEqual(sections[30].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[30].address_align, 0x10)
        self.assertEqual(sections[30].section_type.name, "SHT_PROGBITS")

        #.bss
        self.assertEqual(sections[31].name, ".bss")
        self.assertEqual(sections[31].offset, 0x30a8)
        self.assertEqual(sections[31].address, 0x40c0)
        self.assertEqual(sections[31].size, 0x1140)
        self.assertEqual(sections[31].flags, "WA")  # WRITABLE ALLOC
        self.assertEqual(sections[31].address_align, 0x20)
        self.assertEqual(sections[31].section_type.name, "SHT_NOBITS")

        #.comment
        self.assertEqual(sections[32].name, ".comment")
        self.assertEqual(sections[32].offset, 0x30a8)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x2b)
        self.assertEqual(sections[32].flags, "MS") # MERGE STRINGS
        self.assertEqual(sections[32].address_align, 0x1)
        self.assertEqual(sections[32].section_type.name, "SHT_PROGBITS")

        #.weird.debug
        self.assertEqual(sections[33].name, ".weird.debug")
        self.assertEqual(sections[33].offset, 0x30d3)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x1f)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type.name, "SHT_PROGBITS")

        #.symtab
        self.assertEqual(sections[34].name, ".symtab")
        self.assertEqual(sections[34].offset, 0x30f0)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x3c0)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x8)
        self.assertEqual(sections[34].section_type.name, "SHT_SYMTAB")

        #.strtab
        self.assertEqual(sections[35].name, ".strtab")
        self.assertEqual(sections[35].offset, 0x30f0 + 0x3c0)
        self.assertEqual(sections[35].address, 0x0)
        self.assertEqual(sections[35].size, 0x386)
        self.assertEqual(sections[35].flags, "")
        self.assertEqual(sections[35].address_align, 0x1)
        self.assertEqual(sections[35].section_type.name, "SHT_STRTAB")

        #.shstrtab
        self.assertEqual(sections[36].name, ".shstrtab")
        self.assertEqual(sections[36].offset, 0x30f0 + 0x3c0 + 0x386)
        self.assertEqual(sections[36].address, 0x0)
        self.assertEqual(sections[36].size, 0x153)
        self.assertEqual(sections[36].flags, "")
        self.assertEqual(sections[36].address_align, 0x1)
        self.assertEqual(sections[36].section_type.name, "SHT_STRTAB")

        d.terminate()

    @skipUnless(PLATFORM == "aarch64", "Requires aarch64")
    def test_sections_aarch64(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("sections_test"), aslr=False)
        d.run()

        sections = d.binary.sections

        self.assertEqual(len(sections), 35)

        # SHT_NULL
        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type.name, "SHT_NULL")

        # .interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x2a8)
        self.assertEqual(sections[1].address, 0x2a8)
        self.assertEqual(sections[1].size, 0x1b)
        self.assertEqual(sections[1].flags, "A")
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type.name, "SHT_PROGBITS")

        # .note.weird
        self.assertEqual(sections[2].name, ".note.weird")
        self.assertEqual(sections[2].offset, 0x2d0)
        self.assertEqual(sections[2].address, 0x2d0)
        self.assertEqual(sections[2].size, 0x16)
        self.assertEqual(sections[2].flags, "A")
        self.assertEqual(sections[2].address_align, 0x10)
        self.assertEqual(sections[2].section_type.name, "SHT_NOTE")

        # .note.gnu.build-id
        self.assertEqual(sections[3].name, ".note.gnu.build-id")
        self.assertEqual(sections[3].offset, 0x2e8)
        self.assertEqual(sections[3].address, 0x2e8)
        self.assertEqual(sections[3].size, 0x24)
        self.assertEqual(sections[3].flags, "A")
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type.name, "SHT_NOTE")

        # .note.ABI-tag
        self.assertEqual(sections[4].name, ".note.ABI-tag")
        self.assertEqual(sections[4].offset, 0x30c)
        self.assertEqual(sections[4].address, 0x30c)
        self.assertEqual(sections[4].size, 0x20)
        self.assertEqual(sections[4].flags, "A")
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type.name, "SHT_NOTE")

        # .gnu.hash
        self.assertEqual(sections[5].name, ".gnu.hash")
        self.assertEqual(sections[5].offset, 0x330)
        self.assertEqual(sections[5].address, 0x330)
        self.assertEqual(sections[5].size, 0x1c)
        self.assertEqual(sections[5].flags, "A")
        self.assertEqual(sections[5].address_align, 0x8)
        self.assertEqual(sections[5].section_type.name, "UNKNOWN_0x6FFFFFF6")

        # .dynsym
        self.assertEqual(sections[6].name, ".dynsym")
        self.assertEqual(sections[6].offset, 0x350)
        self.assertEqual(sections[6].address, 0x350)
        self.assertEqual(sections[6].size, 0x138)
        self.assertEqual(sections[6].flags, "A")
        self.assertEqual(sections[6].address_align, 0x8)
        self.assertEqual(sections[6].section_type.name, "SHT_DYNSYM")

        # .dynstr
        self.assertEqual(sections[7].name, ".dynstr")
        self.assertEqual(sections[7].offset, 0x488)
        self.assertEqual(sections[7].address, 0x488)
        self.assertEqual(sections[7].size, 0x0a3)
        self.assertEqual(sections[7].flags, "A")
        self.assertEqual(sections[7].address_align, 0x1)
        self.assertEqual(sections[7].section_type.name, "SHT_STRTAB")

        # .gnu.version
        self.assertEqual(sections[8].name, ".gnu.version")
        self.assertEqual(sections[8].offset, 0x52c)
        self.assertEqual(sections[8].address, 0x52c)
        self.assertEqual(sections[8].size, 0x1a)
        self.assertEqual(sections[8].flags, "A")
        self.assertEqual(sections[8].address_align, 0x2)
        self.assertEqual(sections[8].section_type.name, "SHT_GNU_VERSYM")

        # .gnu.version_r
        self.assertEqual(sections[9].name, ".gnu.version_r")
        self.assertEqual(sections[9].offset, 0x548)
        self.assertEqual(sections[9].address, 0x548)
        self.assertEqual(sections[9].size, 0x30)
        self.assertEqual(sections[9].flags, "A")
        self.assertEqual(sections[9].address_align, 0x8)
        self.assertEqual(sections[9].section_type.name, "SHT_GNU_VERNEED")

        # .rela.dyn
        self.assertEqual(sections[10].name, ".rela.dyn")
        self.assertEqual(sections[10].offset, 0x578)
        self.assertEqual(sections[10].address, 0x578)
        self.assertEqual(sections[10].size, 0x180)
        self.assertEqual(sections[10].flags, "A")
        self.assertEqual(sections[10].address_align, 0x8)
        self.assertEqual(sections[10].section_type.name, "SHT_RELA")

        # .rela.plt
        self.assertEqual(sections[11].name, ".rela.plt")
        self.assertEqual(sections[11].offset, 0x6f8)
        self.assertEqual(sections[11].address, 0x6f8)
        self.assertEqual(sections[11].size, 0xa8)
        self.assertEqual(sections[11].flags, "AI")
        self.assertEqual(sections[11].address_align, 0x8)
        self.assertEqual(sections[11].section_type.name, "SHT_RELA")

        # .init
        self.assertEqual(sections[12].name, ".init")
        self.assertEqual(sections[12].offset, 0x7a0)
        self.assertEqual(sections[12].address, 0x7a0)
        self.assertEqual(sections[12].size, 0x18)
        self.assertEqual(sections[12].flags, "AX")
        self.assertEqual(sections[12].address_align, 0x4)
        self.assertEqual(sections[12].section_type.name, "SHT_PROGBITS")

        # .plt
        self.assertEqual(sections[13].name, ".plt")
        self.assertEqual(sections[13].offset, 0x7c0)
        self.assertEqual(sections[13].address, 0x7c0)
        self.assertEqual(sections[13].size, 0x90)
        self.assertEqual(sections[13].flags, "AX")
        self.assertEqual(sections[13].address_align, 0x10)
        self.assertEqual(sections[13].section_type.name, "SHT_PROGBITS")

        # .text
        self.assertEqual(sections[14].name, ".text")
        self.assertEqual(sections[14].offset, 0x880)
        self.assertEqual(sections[14].address, 0x880)
        self.assertEqual(sections[14].size, 0x2f8)
        self.assertEqual(sections[14].flags, "AX")
        self.assertEqual(sections[14].address_align, 0x40)
        self.assertEqual(sections[14].section_type.name, "SHT_PROGBITS")

        # .fini
        self.assertEqual(sections[15].name, ".fini")
        self.assertEqual(sections[15].offset, 0xb78)
        self.assertEqual(sections[15].address, 0xb78)
        self.assertEqual(sections[15].size, 0x14)
        self.assertEqual(sections[15].flags, "AX")
        self.assertEqual(sections[15].address_align, 0x4)
        self.assertEqual(sections[15].section_type.name, "SHT_PROGBITS")

        # .rodata
        self.assertEqual(sections[16].name, ".rodata")
        self.assertEqual(sections[16].offset, 0xb90)
        self.assertEqual(sections[16].address, 0xb90)
        self.assertEqual(sections[16].size, 0xa6)
        self.assertEqual(sections[16].flags, "A")
        self.assertEqual(sections[16].address_align, 0x8)
        self.assertEqual(sections[16].section_type.name, "SHT_PROGBITS")

        # .eh_frame_hdr
        self.assertEqual(sections[17].name, ".eh_frame_hdr")
        self.assertEqual(sections[17].offset, 0xc38)
        self.assertEqual(sections[17].address, 0xc38)
        self.assertEqual(sections[17].size, 0x64)
        self.assertEqual(sections[17].flags, "A")
        self.assertEqual(sections[17].address_align, 0x4)
        self.assertEqual(sections[17].section_type.name, "SHT_PROGBITS")

        # .eh_frame
        self.assertEqual(sections[18].name, ".eh_frame")
        self.assertEqual(sections[18].offset, 0xca0)
        self.assertEqual(sections[18].address, 0xca0)
        self.assertEqual(sections[18].size, 0x124)
        self.assertEqual(sections[18].flags, "A")
        self.assertEqual(sections[18].address_align, 0x8)
        self.assertEqual(sections[18].section_type.name, "SHT_PROGBITS")

        # .tdata
        self.assertEqual(sections[19].name, ".tdata")
        self.assertEqual(sections[19].offset, 0xfd84)
        self.assertEqual(sections[19].address, 0x1fd84)
        self.assertEqual(sections[19].size, 0x4)
        self.assertEqual(sections[19].flags, "WAT")
        self.assertEqual(sections[19].address_align, 0x4)
        self.assertEqual(sections[19].section_type.name, "SHT_PROGBITS")

        # .tbss
        self.assertEqual(sections[20].name, ".tbss")
        self.assertEqual(sections[20].offset, 0xfd88)
        self.assertEqual(sections[20].address, 0x1fd88)
        self.assertEqual(sections[20].size, 0x4)
        self.assertEqual(sections[20].flags, "WAT")
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type.name, "SHT_NOBITS")

        # .init_array
        self.assertEqual(sections[21].name, ".init_array")
        self.assertEqual(sections[21].offset, 0xfd88)
        self.assertEqual(sections[21].address, 0x1fd88)
        self.assertEqual(sections[21].size, 0x10)
        self.assertEqual(sections[21].flags, "WA")
        self.assertEqual(sections[21].address_align, 0x8)
        self.assertEqual(sections[21].section_type.name, "SHT_INIT_ARRAY")

        # .fini_array
        self.assertEqual(sections[22].name, ".fini_array")
        self.assertEqual(sections[22].offset, 0xfd98)
        self.assertEqual(sections[22].address, 0x1fd98)
        self.assertEqual(sections[22].size, 0x10)
        self.assertEqual(sections[22].flags, "WA")
        self.assertEqual(sections[22].address_align, 0x8)
        self.assertEqual(sections[22].section_type.name, "SHT_FINI_ARRAY")

        # .data.rel.ro
        self.assertEqual(sections[23].name, ".data.rel.ro")
        self.assertEqual(sections[23].offset, 0xfda8)
        self.assertEqual(sections[23].address, 0x1fda8)
        self.assertEqual(sections[23].size, 0x8)
        self.assertEqual(sections[23].flags, "WA")
        self.assertEqual(sections[23].address_align, 0x8)
        self.assertEqual(sections[23].section_type.name, "SHT_PROGBITS")

        # .dynamic
        self.assertEqual(sections[24].name, ".dynamic")
        self.assertEqual(sections[24].offset, 0xfdb0)
        self.assertEqual(sections[24].address, 0x1fdb0)
        self.assertEqual(sections[24].size, 0x1e0)
        self.assertEqual(sections[24].flags, "WA")
        self.assertEqual(sections[24].address_align, 0x8)
        self.assertEqual(sections[24].section_type.name, "SHT_DYNAMIC")

        # .got
        self.assertEqual(sections[25].name, ".got")
        self.assertEqual(sections[25].offset, 0xff90)
        self.assertEqual(sections[25].address, 0x1ff90)
        self.assertEqual(sections[25].size, 0x58)
        self.assertEqual(sections[25].flags, "WA")
        self.assertEqual(sections[25].address_align, 0x8)
        self.assertEqual(sections[25].section_type.name, "SHT_PROGBITS")

        # .got.plt
        self.assertEqual(sections[26].name, ".got.plt")
        self.assertEqual(sections[26].offset, 0xffe8)
        self.assertEqual(sections[26].address, 0x1ffe8)
        self.assertEqual(sections[26].size, 0x50)
        self.assertEqual(sections[26].flags, "WA")
        self.assertEqual(sections[26].address_align, 0x8)
        self.assertEqual(sections[26].section_type.name, "SHT_PROGBITS")

        # .data
        self.assertEqual(sections[27].name, ".data")
        self.assertEqual(sections[27].offset, 0x10040)
        self.assertEqual(sections[27].address, 0x20040)
        self.assertEqual(sections[27].size, 0xa0)
        self.assertEqual(sections[27].flags, "WA")
        self.assertEqual(sections[27].address_align, 0x40)
        self.assertEqual(sections[27].section_type.name, "SHT_PROGBITS")

        # .extra.data
        self.assertEqual(sections[28].name, ".extra.data")
        self.assertEqual(sections[28].offset, 0x20000)
        self.assertEqual(sections[28].address, 0x30000)
        self.assertEqual(sections[28].size, 0x8)
        self.assertEqual(sections[28].flags, "WA")
        self.assertEqual(sections[28].address_align, 0x10000)
        self.assertEqual(sections[28].section_type.name, "SHT_PROGBITS")

        # .bss
        self.assertEqual(sections[29].name, ".bss")
        self.assertEqual(sections[29].offset, 0x20008)
        self.assertEqual(sections[29].address, 0x30008)
        self.assertEqual(sections[29].size, 0x1120)
        self.assertEqual(sections[29].flags, "WA")
        self.assertEqual(sections[29].address_align, 0x8)
        self.assertEqual(sections[29].section_type.name, "SHT_NOBITS")

        # .comment
        self.assertEqual(sections[30].name, ".comment")
        self.assertEqual(sections[30].offset, 0x20008)
        self.assertEqual(sections[30].address, 0x0)
        self.assertEqual(sections[30].size, 0x27)
        self.assertEqual(sections[30].flags, "MS")
        self.assertEqual(sections[30].address_align, 0x1)
        self.assertEqual(sections[30].section_type.name, "SHT_PROGBITS")

        # .weird.debug
        self.assertEqual(sections[31].name, ".weird.debug")
        self.assertEqual(sections[31].offset, 0x2002f)
        self.assertEqual(sections[31].address, 0x0)
        self.assertEqual(sections[31].size, 0x1f)
        self.assertEqual(sections[31].flags, "")
        self.assertEqual(sections[31].address_align, 0x1)
        self.assertEqual(sections[31].section_type.name, "SHT_PROGBITS")

        # .symtab
        self.assertEqual(sections[32].name, ".symtab")
        self.assertEqual(sections[32].offset, 0x20050)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x0cd8)
        self.assertEqual(sections[32].flags, "")
        self.assertEqual(sections[32].address_align, 0x8)
        self.assertEqual(sections[32].section_type.name, "SHT_SYMTAB")

        # .strtab
        self.assertEqual(sections[33].name, ".strtab")
        self.assertEqual(sections[33].offset, 0x20d28)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x038d)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type.name, "SHT_STRTAB")

        # .shstrtab
        self.assertEqual(sections[34].name, ".shstrtab")
        self.assertEqual(sections[34].offset, 0x210b5)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x013c)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x1)
        self.assertEqual(sections[34].section_type.name, "SHT_STRTAB")

        d.terminate()

    @skipUnless(PLATFORM == "i386", "Requires i3866")
    def test_sections_i386(self):
        """Tests the sections API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("sections_test"), aslr=False)
        d.run()

        sections = d.binary.sections

        self.assertEqual(len(sections), 35)

        # SHT_NULL
        self.assertEqual(sections[0].name, "")
        self.assertEqual(sections[0].offset, 0x0)
        self.assertEqual(sections[0].address, 0x0)
        self.assertEqual(sections[0].size, 0x0)
        self.assertEqual(sections[0].flags, "")  # None
        self.assertEqual(sections[0].address_align, 0x0)
        self.assertEqual(sections[0].section_type.name, "SHT_NULL")

        # .interp
        self.assertEqual(sections[1].name, ".interp")
        self.assertEqual(sections[1].offset, 0x1b4)
        self.assertEqual(sections[1].address, 0x1b4)
        self.assertEqual(sections[1].size, 0x13)
        self.assertEqual(sections[1].flags, "A")
        self.assertEqual(sections[1].address_align, 0x1)
        self.assertEqual(sections[1].section_type.name, "SHT_PROGBITS")

        # .note.gnu.build-id
        self.assertEqual(sections[2].name, ".note.gnu.build-id")
        self.assertEqual(sections[2].offset, 0x1c8)
        self.assertEqual(sections[2].address, 0x1c8)
        self.assertEqual(sections[2].size, 0x24)
        self.assertEqual(sections[2].flags, "A")
        self.assertEqual(sections[2].address_align, 0x4)
        self.assertEqual(sections[2].section_type.name, "SHT_NOTE")

        # .note.ABI-tag
        self.assertEqual(sections[3].name, ".note.ABI-tag")
        self.assertEqual(sections[3].offset, 0x1ec)
        self.assertEqual(sections[3].address, 0x1ec)
        self.assertEqual(sections[3].size, 0x20)
        self.assertEqual(sections[3].flags, "A")
        self.assertEqual(sections[3].address_align, 0x4)
        self.assertEqual(sections[3].section_type.name, "SHT_NOTE")

        # .note.weird
        self.assertEqual(sections[4].name, ".note.weird")
        self.assertEqual(sections[4].offset, 0x20c)
        self.assertEqual(sections[4].address, 0x20c)
        self.assertEqual(sections[4].size, 0x16)
        self.assertEqual(sections[4].flags, "A")
        self.assertEqual(sections[4].address_align, 0x4)
        self.assertEqual(sections[4].section_type.name, "SHT_NOTE")

        # .gnu.hash
        self.assertEqual(sections[5].name, ".gnu.hash")
        self.assertEqual(sections[5].offset, 0x224)
        self.assertEqual(sections[5].address, 0x224)
        self.assertEqual(sections[5].size, 0x20)
        self.assertEqual(sections[5].flags, "A")
        self.assertEqual(sections[5].address_align, 0x4)
        self.assertEqual(sections[5].section_type.name, "UNKNOWN_0x6FFFFFF6")

        # .dynsym
        self.assertEqual(sections[6].name, ".dynsym")
        self.assertEqual(sections[6].offset, 0x244)
        self.assertEqual(sections[6].address, 0x244)
        self.assertEqual(sections[6].size, 0xC0)
        self.assertEqual(sections[6].flags, "A")
        self.assertEqual(sections[6].address_align, 0x4)
        self.assertEqual(sections[6].section_type.name, "SHT_DYNSYM")

        # .dynstr
        self.assertEqual(sections[7].name, ".dynstr")
        self.assertEqual(sections[7].offset, 0x304)
        self.assertEqual(sections[7].address, 0x304)
        self.assertEqual(sections[7].size, 0xFE)
        self.assertEqual(sections[7].flags, "A")
        self.assertEqual(sections[7].address_align, 0x1)
        self.assertEqual(sections[7].section_type.name, "SHT_STRTAB")

        # .gnu.version
        self.assertEqual(sections[8].name, ".gnu.version")
        self.assertEqual(sections[8].offset, 0x402)
        self.assertEqual(sections[8].address, 0x402)
        self.assertEqual(sections[8].size, 0x18)
        self.assertEqual(sections[8].flags, "A")
        self.assertEqual(sections[8].address_align, 0x2)
        self.assertEqual(sections[8].section_type.name, "SHT_GNU_VERSYM")

        # .gnu.version_r
        self.assertEqual(sections[9].name, ".gnu.version_r")
        self.assertEqual(sections[9].offset, 0x41C)
        self.assertEqual(sections[9].address, 0x41C)
        self.assertEqual(sections[9].size, 0x70)
        self.assertEqual(sections[9].flags, "A")
        self.assertEqual(sections[9].address_align, 0x4)
        self.assertEqual(sections[9].section_type.name, "SHT_GNU_VERNEED")

        # .rel.dyn
        self.assertEqual(sections[10].name, ".rel.dyn")
        self.assertEqual(sections[10].offset, 0x48C)
        self.assertEqual(sections[10].address, 0x48C)
        self.assertEqual(sections[10].size, 0x68)
        self.assertEqual(sections[10].flags, "A")
        self.assertEqual(sections[10].address_align, 0x4)
        self.assertEqual(sections[10].section_type.name, "SHT_REL")

        # .rel.plt
        self.assertEqual(sections[11].name, ".rel.plt")
        self.assertEqual(sections[11].offset, 0x4F4)
        self.assertEqual(sections[11].address, 0x4F4)
        self.assertEqual(sections[11].size, 0x28)
        self.assertEqual(sections[11].flags, "AI")
        self.assertEqual(sections[11].address_align, 0x4)
        self.assertEqual(sections[11].section_type.name, "SHT_REL")

        # .init
        self.assertEqual(sections[12].name, ".init")
        self.assertEqual(sections[12].offset, 0x1000)
        self.assertEqual(sections[12].address, 0x1000)
        self.assertEqual(sections[12].size, 0x20)
        self.assertEqual(sections[12].flags, "AX")
        self.assertEqual(sections[12].address_align, 0x4)
        self.assertEqual(sections[12].section_type.name, "SHT_PROGBITS")

        # .plt
        self.assertEqual(sections[13].name, ".plt")
        self.assertEqual(sections[13].offset, 0x1020)
        self.assertEqual(sections[13].address, 0x1020)
        self.assertEqual(sections[13].size, 0x60)
        self.assertEqual(sections[13].flags, "AX")
        self.assertEqual(sections[13].address_align, 0x10)
        self.assertEqual(sections[13].section_type.name, "SHT_PROGBITS")

        # .plt.got
        self.assertEqual(sections[14].name, ".plt.got")
        self.assertEqual(sections[14].offset, 0x1080)
        self.assertEqual(sections[14].address, 0x1080)
        self.assertEqual(sections[14].size, 0x8)
        self.assertEqual(sections[14].flags, "AX")
        self.assertEqual(sections[14].address_align, 0x8)
        self.assertEqual(sections[14].section_type.name, "SHT_PROGBITS")

        # .text
        self.assertEqual(sections[15].name, ".text")
        self.assertEqual(sections[15].offset, 0x1090)
        self.assertEqual(sections[15].address, 0x1090)
        self.assertEqual(sections[15].size, 0x2DA)
        self.assertEqual(sections[15].flags, "AX")
        self.assertEqual(sections[15].address_align, 0x10)
        self.assertEqual(sections[15].section_type.name, "SHT_PROGBITS")

        # .fini
        self.assertEqual(sections[16].name, ".fini")
        self.assertEqual(sections[16].offset, 0x136C)
        self.assertEqual(sections[16].address, 0x136C)
        self.assertEqual(sections[16].size, 0x14)
        self.assertEqual(sections[16].flags, "AX")
        self.assertEqual(sections[16].address_align, 0x4)
        self.assertEqual(sections[16].section_type.name, "SHT_PROGBITS")

        # .rodata
        self.assertEqual(sections[17].name, ".rodata")
        self.assertEqual(sections[17].offset, 0x2000)
        self.assertEqual(sections[17].address, 0x2000)
        self.assertEqual(sections[17].size, 0x9A)
        self.assertEqual(sections[17].flags, "A")
        self.assertEqual(sections[17].address_align, 0x4)
        self.assertEqual(sections[17].section_type.name, "SHT_PROGBITS")

        # .eh_frame_hdr
        self.assertEqual(sections[18].name, ".eh_frame_hdr")
        self.assertEqual(sections[18].offset, 0x209C)
        self.assertEqual(sections[18].address, 0x209C)
        self.assertEqual(sections[18].size, 0x5C)
        self.assertEqual(sections[18].flags, "A")
        self.assertEqual(sections[18].address_align, 0x4)
        self.assertEqual(sections[18].section_type.name, "SHT_PROGBITS")

        # .eh_frame
        self.assertEqual(sections[19].name, ".eh_frame")
        self.assertEqual(sections[19].offset, 0x20F8)
        self.assertEqual(sections[19].address, 0x20F8)
        self.assertEqual(sections[19].size, 0x1A0)
        self.assertEqual(sections[19].flags, "A")
        self.assertEqual(sections[19].address_align, 0x4)
        self.assertEqual(sections[19].section_type.name, "SHT_PROGBITS")

        # .tdata
        self.assertEqual(sections[20].name, ".tdata")
        self.assertEqual(sections[20].offset, 0x2EAC)
        self.assertEqual(sections[20].address, 0x3EAC)
        self.assertEqual(sections[20].size, 0x4)
        self.assertEqual(sections[20].flags, "WAT")
        self.assertEqual(sections[20].address_align, 0x4)
        self.assertEqual(sections[20].section_type.name, "SHT_PROGBITS")

        # .tbss
        self.assertEqual(sections[21].name, ".tbss")
        self.assertEqual(sections[21].offset, 0x2EB0)
        self.assertEqual(sections[21].address, 0x3EB0)
        self.assertEqual(sections[21].size, 0x4)
        self.assertEqual(sections[21].flags, "WAT")
        self.assertEqual(sections[21].address_align, 0x4)
        self.assertEqual(sections[21].section_type.name, "SHT_NOBITS")

        # .init_array
        self.assertEqual(sections[22].name, ".init_array")
        self.assertEqual(sections[22].offset, 0x2EB0)
        self.assertEqual(sections[22].address, 0x3EB0)
        self.assertEqual(sections[22].size, 0x8)
        self.assertEqual(sections[22].flags, "WA")
        self.assertEqual(sections[22].address_align, 0x4)
        self.assertEqual(sections[22].section_type.name, "SHT_INIT_ARRAY")

        # .fini_array
        self.assertEqual(sections[23].name, ".fini_array")
        self.assertEqual(sections[23].offset, 0x2EB8)
        self.assertEqual(sections[23].address, 0x3EB8)
        self.assertEqual(sections[23].size, 0x8)
        self.assertEqual(sections[23].flags, "WA")
        self.assertEqual(sections[23].address_align, 0x4)
        self.assertEqual(sections[23].section_type.name, "SHT_FINI_ARRAY")

        # .data.rel.ro
        self.assertEqual(sections[24].name, ".data.rel.ro")
        self.assertEqual(sections[24].offset, 0x2EC0)
        self.assertEqual(sections[24].address, 0x3EC0)
        self.assertEqual(sections[24].size, 0x4)
        self.assertEqual(sections[24].flags, "WA")
        self.assertEqual(sections[24].address_align, 0x4)
        self.assertEqual(sections[24].section_type.name, "SHT_PROGBITS")

        # .dynamic
        self.assertEqual(sections[25].name, ".dynamic")
        self.assertEqual(sections[25].offset, 0x2EC4)
        self.assertEqual(sections[25].address, 0x3EC4)
        self.assertEqual(sections[25].size, 0x100)
        self.assertEqual(sections[25].flags, "WA")
        self.assertEqual(sections[25].address_align, 0x4)
        self.assertEqual(sections[25].section_type.name, "SHT_DYNAMIC")

        # .got
        self.assertEqual(sections[26].name, ".got")
        self.assertEqual(sections[26].offset, 0x2FC4)
        self.assertEqual(sections[26].address, 0x3FC4)
        self.assertEqual(sections[26].size, 0x3C)
        self.assertEqual(sections[26].flags, "WA")
        self.assertEqual(sections[26].address_align, 0x4)
        self.assertEqual(sections[26].section_type.name, "SHT_PROGBITS")

        # .data
        self.assertEqual(sections[27].name, ".data")
        self.assertEqual(sections[27].offset, 0x3000)
        self.assertEqual(sections[27].address, 0x4000)
        self.assertEqual(sections[27].size, 0xA0)
        self.assertEqual(sections[27].flags, "WA")
        self.assertEqual(sections[27].address_align, 0x40)
        self.assertEqual(sections[27].section_type.name, "SHT_PROGBITS")

        # .extra.data
        self.assertEqual(sections[28].name, ".extra.data")
        self.assertEqual(sections[28].offset, 0x30A0)
        self.assertEqual(sections[28].address, 0x40A0)
        self.assertEqual(sections[28].size, 0x8)
        self.assertEqual(sections[28].flags, "WA")
        self.assertEqual(sections[28].address_align, 0x10)
        self.assertEqual(sections[28].section_type.name, "SHT_PROGBITS")

        # .bss
        self.assertEqual(sections[29].name, ".bss")
        self.assertEqual(sections[29].offset, 0x30A8)
        self.assertEqual(sections[29].address, 0x40C0)
        self.assertEqual(sections[29].size, 0x1140)
        self.assertEqual(sections[29].flags, "WA")
        self.assertEqual(sections[29].address_align, 0x20)
        self.assertEqual(sections[29].section_type.name, "SHT_NOBITS")

        # .comment
        self.assertEqual(sections[30].name, ".comment")
        self.assertEqual(sections[30].offset, 0x30A8)
        self.assertEqual(sections[30].address, 0x0)
        self.assertEqual(sections[30].size, 0x2B)
        self.assertEqual(sections[30].flags, "MS")
        self.assertEqual(sections[30].address_align, 0x1)
        self.assertEqual(sections[30].section_type.name, "SHT_PROGBITS")

        # .weird.debug
        self.assertEqual(sections[31].name, ".weird.debug")
        self.assertEqual(sections[31].offset, 0x30D3)
        self.assertEqual(sections[31].address, 0x0)
        self.assertEqual(sections[31].size, 0x1F)
        self.assertEqual(sections[31].flags, "")
        self.assertEqual(sections[31].address_align, 0x1)
        self.assertEqual(sections[31].section_type.name, "SHT_PROGBITS")

        # .symtab
        self.assertEqual(sections[32].name, ".symtab")
        self.assertEqual(sections[32].offset, 0x30F4)
        self.assertEqual(sections[32].address, 0x0)
        self.assertEqual(sections[32].size, 0x410)
        self.assertEqual(sections[32].flags, "")
        self.assertEqual(sections[32].address_align, 0x4)
        self.assertEqual(sections[32].section_type.name, "SHT_SYMTAB")

        # .strtab
        self.assertEqual(sections[33].name, ".strtab")
        self.assertEqual(sections[33].offset, 0x3504)
        self.assertEqual(sections[33].address, 0x0)
        self.assertEqual(sections[33].size, 0x3B6)
        self.assertEqual(sections[33].flags, "")
        self.assertEqual(sections[33].address_align, 0x1)
        self.assertEqual(sections[33].section_type.name, "SHT_STRTAB")

        # .shstrtab
        self.assertEqual(sections[34].name, ".shstrtab")
        self.assertEqual(sections[34].offset, 0x38BA)
        self.assertEqual(sections[34].address, 0x0)
        self.assertEqual(sections[34].size, 0x135)
        self.assertEqual(sections[34].flags, "")
        self.assertEqual(sections[34].address_align, 0x1)
        self.assertEqual(sections[34].section_type.name, "SHT_STRTAB")

        d.terminate()

    def test_binary_and_libs_api(self):
        """Tests the binary and libraries API."""
        # Create a debugger and start execution
        d = debugger(RESOLVE_EXE("sections_test"), aslr=False)

        self.assertEqual(d.binary.path.split("/")[-1], "sections_test")
        self.assertEqual(d.binary.architecture, PLATFORM)
        self.assertEqual(d.binary.base_address, BASE)
        self.assertEqual(d.binary.is_pie, True)
        self.assertEqual(d.binary.entry_point, 0x1000)
        self.assertEqual(d.binary.endianness, "little")
        self.assertEqual(d.binary.build_id, "de1a4f0ca53a82f9590cc4a3cfaaec5fe86aabaf")

        self.assertRaises(ValueError, lambda: d.binary.symbols)
        self.assertRaises(RuntimeError, lambda: d.libraries)
        self.assertRaises(RuntimeError, lambda: d.libs)

        d.run()

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

        self.assertEqual(d.binary.path, RESOLVE_EXE("sections_test"))
        self.assertEqual(len(d.libraries), 2)

        d.terminate()