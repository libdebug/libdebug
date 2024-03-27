#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


def get_reg_64(dict: object, name: str) -> int:
    return getattr(dict, name)


def get_reg_32(dict: object, name: str) -> int:
    return getattr(dict, name) & 0xFFFFFFFF


def get_reg_16(dict: object, name: str) -> int:
    return getattr(dict, name) & 0xFFFF


def get_reg_8l(dict: object, name: str) -> int:
    return getattr(dict, name) & 0xFF


def get_reg_8h(dict: object, name: str) -> int:
    return (getattr(dict, name) >> 8) & 0xFF


def set_reg_64(dict: object, name: str, value: int):
    setattr(dict, name, value)


def set_reg_32(dict: object, name: str, value: int):
    setattr(
        dict, name, (getattr(dict, name) & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF)
    )


def set_reg_16(dict: object, name: str, value: int):
    setattr(dict, name, (getattr(dict, name) & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF))


def set_reg_8l(dict: object, name: str, value: int):
    setattr(dict, name, (getattr(dict, name) & 0xFFFFFFFFFFFFFF00) | (value & 0xFF))


def set_reg_8h(dict: object, name: str, value: int):
    setattr(
        dict, name, (getattr(dict, name) & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
    )
