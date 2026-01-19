#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini, Francesco Panebianco, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import sys
from multiprocessing import set_start_method

from libdebug import debugger
from libdebug.utils.libcontext import libcontext
from pathlib import Path


PLATFORM = os.getenv("PLATFORM", libcontext.platform)

def RESOLVE_EXE(file: str) -> str:
    return f"binaries/{PLATFORM}/{file}"

def _base_address() -> int:
    d = debugger(RESOLVE_EXE("basic_test_pie"), aslr=False)

    d.run()

    base = d.maps[0].start

    d.kill()
    d.terminate()

    return base

def base_of(d) -> int:
    return d.maps[0].start

BASE = _base_address()

CPUINFO = Path("/proc/cpuinfo").read_text()

# Python 3.14 changed the default start method on Unix to 'forkserver', but this breaks our tests
# Not sure why they would do that, because now functions cannot be easily pickled and this is
# a huge limitation
if sys.version_info >= (3, 14):
    set_start_method('fork')