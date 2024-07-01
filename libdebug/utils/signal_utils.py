#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import signal


@functools.cache
def create_signal_mappings() -> tuple[dict, dict]:
    """Create mappings between signal names and numbers."""
    signal_to_number = {}
    number_to_signal = {}

    for name in dir(signal):
        if name.startswith("SIG") and not name.startswith("SIG_"):
            number = getattr(signal, name)
            signal_to_number[name] = number
            number_to_signal[number] = name

    return signal_to_number, number_to_signal


@functools.cache
def resolve_signal_number(name: str) -> int:
    """Resolve a signal name to its number.

    Args:
        name (str): the signal name.

    Returns:
        int: the signal number.
    """
    signal_to_number, _ = create_signal_mappings()

    try:
        return signal_to_number[name]
    except KeyError as e:
        raise ValueError(f"Signal {name} not found.") from e


@functools.cache
def resolve_signal_name(number: int) -> str:
    """Resolve a signal number to its name.

    Args:
        number (int): the signal number.

    Returns:
        str: the signal name.
    """
    _, number_to_signal = create_signal_mappings()

    try:
        return number_to_signal[number]
    except KeyError as e:
        raise ValueError(f"Signal {number} not found.") from e


@functools.cache
def get_all_signal_numbers() -> list:
    """Get all the signal numbers.

    Returns:
        list: the list of signal numbers.
    """
    _, number_to_signal = create_signal_mappings()

    return list(number_to_signal.keys())
