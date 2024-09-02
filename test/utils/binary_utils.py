#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug import debugger
from libdebug.utils.libcontext import libcontext

def RESOLVE_EXE(file: str) -> str:
    return f"binaries/{libcontext.platform}/{file}"

def _base_address() -> int:
    d = debugger(RESOLVE_EXE("basic_test_pie"))

    d.run()

    base = d.maps()[0].start

    d.kill()
    d.terminate()

    return base

BASE = _base_address()
