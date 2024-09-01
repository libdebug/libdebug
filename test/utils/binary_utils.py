#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.utils.libcontext import libcontext

def RESOLVE_EXE(file: str) -> str:
    return f"binaries/{libcontext.platform}/{file}"
