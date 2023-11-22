#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
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


def get_reg_64(dict: dict, name: str) -> int:
    return dict[name]


def get_reg_32(dict: dict, name: str) -> int:
    return dict[name] & 0xFFFFFFFF


def get_reg_16(dict: dict, name: str) -> int:
    return dict[name] & 0xFFFF


def get_reg_8l(dict: dict, name: str) -> int:
    return dict[name] & 0xFF


def get_reg_8h(dict: dict, name: str) -> int:
    return (dict[name] >> 8) & 0xFF


def set_reg_64(dict: dict, name: str, value: int):
    dict[name] = value


def set_reg_32(dict: dict, name: str, value: int):
    dict[name] = (dict[name] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)


def set_reg_16(dict: dict, name: str, value: int):
    dict[name] = (dict[name] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)


def set_reg_8l(dict: dict, name: str, value: int):
    dict[name] = (dict[name] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)


def set_reg_8h(dict: dict, name: str, value: int):
    dict[name] = (dict[name] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
