#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from unittest import TestCase
from utils.binary_utils import RESOLVE_EXE

from libdebug import debugger


class CorruptedELFTest(TestCase):
    def test_basic_corrupted_elf(self):
        d = debugger(RESOLVE_EXE("corrupted_elf_test"))

        r = d.run()

        self.assertEqual(r.recvline(), b"Provola!")

        d.kill()
