#
# This file is part of libdebug Python library (https://github.com/gabriele180698/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import unittest
from tests.basic_test import BasicTest, BasicPieTest
from tests.breakpoint_test import BreakpointTest

def suite():
    suite = unittest.TestSuite()
    suite.addTest(BasicTest('test_basic'))
    suite.addTest(BasicTest('test_registers'))
    suite.addTest(BasicPieTest('test_basic'))
    suite.addTest(BreakpointTest('test_bps'))
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suite())
