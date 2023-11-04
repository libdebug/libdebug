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

def get_reg_64(dict, name):
    return dict[name]

def get_reg_32(dict, name):
    return dict[name] & 0xffffffff

def get_reg_16(dict, name):
    return dict[name] & 0xffff

def get_reg_8l(dict, name):
    return dict[name] & 0xff

def get_reg_8h(dict, name):
    return (dict[name] >> 8) & 0xff

def set_reg_64(dict, name, value):
    dict[name] = value

def set_reg_32(dict, name, value):
    dict[name] = (dict[name] & 0xffffffff00000000) | (value & 0xffffffff)

def set_reg_16(dict, name, value):
    dict[name] = (dict[name] & 0xffffffffffff0000) | (value & 0xffff)

def set_reg_8l(dict, name, value):
    dict[name] = (dict[name] & 0xffffffffffffff00) | (value & 0xff)

def set_reg_8h(dict, name, value):
    dict[name] = (dict[name] & 0xffffffffffff00ff) | ((value & 0xff) << 8)