//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "binary_utils.h"

int host_is_le(void) {
    uint16_t x = 1;
    return *(uint8_t*)&x == 1;
}

uint16_t bswap16(uint16_t x){ return (uint16_t)((x<<8)|(x>>8)); }
uint32_t bswap32(uint32_t x){ return ((x&0x000000FFu)<<24)|((x&0x0000FF00u)<<8)|((x&0x00FF0000u)>>8)|((x&0xFF000000u)>>24); }
uint64_t bswap64(uint64_t x){
    return ((uint64_t)bswap32((uint32_t)(x&0xFFFFFFFFull))<<32) | (uint64_t)bswap32((uint32_t)(x>>32));
}
uint16_t maybe16(uint16_t v, int swap){ return swap ? bswap16(v) : v; }
uint32_t maybe32(uint32_t v, int swap){ return swap ? bswap32(v) : v; }
uint64_t maybe64(uint64_t v, int swap){ return swap ? bswap64(v) : v; }

int is_p2(uint64_t x){ return x && ((x & (x - 1)) == 0); }

void read_file_or_throw(const char *path, std::vector<uint8_t> &buf){
    FILE *f = fopen(path, "rb");
    if (!f) throw std::runtime_error("Failed to open ELF file for section parsing");
    if (fseek(f, 0, SEEK_END)) { fclose(f); throw std::runtime_error("fseek failed"); }
    long n = ftell(f);
    if (n < 0) { fclose(f); throw std::runtime_error("ftell failed"); }
    if (fseek(f, 0, SEEK_SET)) { fclose(f); throw std::runtime_error("fseek failed"); }
    buf.resize(n > 0 ? (size_t)n : 1);
    size_t rd = fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    if (rd != buf.size()) throw std::runtime_error("Short read");
}

int in_bounds(size_t off, size_t len, size_t file_sz){
    if (off > file_sz) return 0;
    if (len > file_sz - off) return 0;
    return 1;
}
