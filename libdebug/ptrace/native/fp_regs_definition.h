//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <nanobind/nanobind.h>

namespace nb = nanobind;

struct PtraceFPRegsStructDefinition
{
    size_t struct_size;
    off_t avx_ymm0_offset;
    off_t avx512_zmm0_offset;
    off_t avx512_zmm1_offset;
    unsigned char type;
    bool has_xsave;
};