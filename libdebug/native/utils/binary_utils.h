//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

int host_is_le(void);

uint16_t bswap16(uint16_t x);
uint32_t bswap32(uint32_t x);
uint64_t bswap64(uint64_t x);
uint16_t maybe16(uint16_t v, int swap);
uint32_t maybe32(uint32_t v, int swap);
uint64_t maybe64(uint64_t v, int swap);
int is_p2(uint64_t x);

void read_file_or_throw(const char *path, std::vector<uint8_t> &buf);
int in_bounds(size_t off, size_t len, size_t file_sz);