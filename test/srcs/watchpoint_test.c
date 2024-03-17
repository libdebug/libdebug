// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2024 Roberto Alessandro Bertolini.
// 
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, version 3.
// 
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <http://www.gnu.org/licenses/>.
// 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint8_t global_char = 0;
uint16_t global_short = 0;
uint32_t global_int = 0;
uint64_t global_long = 0;

int main()
{
    global_char = 0x01;
    global_short = 0x0203;
    global_int = 0x04050607;
    global_long = 0x08090a0b0c0d0e0f;

    uint8_t local_char = 0;
    uint16_t local_short = 0;
    uint32_t local_int = 0;
    uint64_t local_long = 0;

    local_char = global_char;
    local_short = global_short;
    local_int = global_int;
    local_long = global_long;

    return 0;
}
