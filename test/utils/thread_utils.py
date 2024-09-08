#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from utils.binary_utils import PLATFORM

def FUN_ARG_0(t) -> int:
    match PLATFORM:
        case "amd64":
            return t.regs.rdi
        case "aarch64":
            return t.regs.x0
        case "i386":
            return int.from_bytes(t.mem[t.regs.esp + 4, 4], "little")
        case _:
            raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")
        
def FUN_RET_VAL(t) -> int:
    match PLATFORM:
        case "amd64":
            return t.regs.rax
        case "aarch64":
            return t.regs.x0
        case "i386":
            return t.regs.eax
        case _:
            raise NotImplementedError(f"Platform {PLATFORM} not supported by this test")
