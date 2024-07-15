#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import unittest

from libdebug import debugger


class BasicTest(unittest.TestCase):

    def test_basic(self):
        d = debugger("binaries/basic_test")
        d.run()
        bp = d.breakpoint("register_test")
        d.cont()
        assert bp.address == d.regs.pc
        d.cont()
        d.kill()
        d.terminate()