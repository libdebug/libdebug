#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger

class BasicTestPie(unittest.TestCase):
    def test_basic(self):
        d = debugger("binaries/basic_test_pie")

        d.run()
        bp = d.breakpoint(0x964, file="binary")
        d.cont()

        assert bp.address == d.regs.pc
        assert d.regs.x0 == 0x4444333322221111

        d.cont()
        d.kill()
        d.terminate()