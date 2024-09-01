#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BasicTestHw(unittest.TestCase):
    def test_basic(self):
        d = debugger("binaries/basic_test")
        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()
        assert bp.address == d.regs.pc
        d.cont()
        d.kill()
        d.terminate()

    def test_registers(self):
        d = debugger("binaries/basic_test")
        d.run()

        bp = d.breakpoint(0x4008a4, hardware=True)

        d.cont()

        assert d.regs.pc == bp.address

        assert d.regs.x0 == 0x4444333322221111
        assert d.regs.x1 == 0x8888777766665555
        assert d.regs.x2 == 0xccccbbbbaaaa9999
        assert d.regs.x3 == 0x1111ffffeeeedddd
        assert d.regs.x4 == 0x5555444433332222
        assert d.regs.x5 == 0x9999888877776666
        assert d.regs.x6 == 0xddddccccbbbbaaaa
        assert d.regs.x7 == 0x22221111ffffeeee
        assert d.regs.x8 == 0x6666555544443333
        assert d.regs.x9 == 0xaaaa999988887777
        assert d.regs.x10 == 0xeeeeddddccccbbbb
        assert d.regs.x11 == 0x333322221111ffff
        assert d.regs.x12 == 0x7777666655554444
        assert d.regs.x13 == 0xbbbbaaaa99998888
        assert d.regs.x14 == 0xffffeeeeddddcccc
        assert d.regs.x15 == 0x4444333322221111
        assert d.regs.x16 == 0x8888777766665555
        assert d.regs.x17 == 0xccccbbbbaaaa9999
        assert d.regs.x18 == 0x1111ffffeeeedddd
        assert d.regs.x19 == 0x5555444433332222
        assert d.regs.x20 == 0x9999888877776666
        assert d.regs.x21 == 0xddddccccbbbbaaaa
        assert d.regs.x22 == 0x22221111ffffeeee
        assert d.regs.x23 == 0x6666555544443333
        assert d.regs.x24 == 0xaaaa999988887777
        assert d.regs.x25 == 0xeeeeddddccccbbbb
        assert d.regs.x26 == 0x333322221111ffff
        assert d.regs.x27 == 0x7777666655554444
        assert d.regs.x28 == 0xbbbbaaaa99998888
        assert d.regs.x29 == 0xffffeeeeddddcccc
        assert d.regs.x30 == 0x4444333322221111

        assert d.regs.w0 == 0x22221111
        assert d.regs.w1 == 0x66665555
        assert d.regs.w2 == 0xaaaa9999
        assert d.regs.w3 == 0xeeeedddd
        assert d.regs.w4 == 0x33332222
        assert d.regs.w5 == 0x77776666
        assert d.regs.w6 == 0xbbbbaaaa
        assert d.regs.w7 == 0xffffeeee
        assert d.regs.w8 == 0x44443333
        assert d.regs.w9 == 0x88887777
        assert d.regs.w10 == 0xccccbbbb
        assert d.regs.w11 == 0x1111ffff
        assert d.regs.w12 == 0x55554444
        assert d.regs.w13 == 0x99998888
        assert d.regs.w14 == 0xddddcccc
        assert d.regs.w15 == 0x22221111
        assert d.regs.w16 == 0x66665555
        assert d.regs.w17 == 0xaaaa9999
        assert d.regs.w18 == 0xeeeedddd
        assert d.regs.w19 == 0x33332222
        assert d.regs.w20 == 0x77776666
        assert d.regs.w21 == 0xbbbbaaaa
        assert d.regs.w22 == 0xffffeeee
        assert d.regs.w23 == 0x44443333
        assert d.regs.w24 == 0x88887777
        assert d.regs.w25 == 0xccccbbbb
        assert d.regs.w26 == 0x1111ffff
        assert d.regs.w27 == 0x55554444
        assert d.regs.w28 == 0x99998888
        assert d.regs.w29 == 0xddddcccc
        assert d.regs.w30 == 0x22221111

        d.cont()

        d.kill()
        d.terminate()

    def test_step(self):
        d = debugger("binaries/basic_test")

        d.run()
        bp = d.breakpoint("register_test", hardware=True)
        d.cont()

        assert bp.address == d.regs.pc
        assert bp.hit_count == 1

        d.step()

        assert (bp.address + 4) == d.regs.pc
        assert bp.hit_count == 1

        d.step()

        assert (bp.address + 8) == d.regs.pc
        assert bp.hit_count == 1

        d.kill()
        d.terminate()