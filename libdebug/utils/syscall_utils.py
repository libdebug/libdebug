#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import json
from pathlib import Path

STATIC_FOLDER_PATH = Path(__file__).parent / "syscall_data"


@functools.cache
def get_syscall_definitions(arch: str) -> dict:
    """Get the syscall definitions for the specified architecture."""
    local_file_path = STATIC_FOLDER_PATH / f"{arch}.json"

    if not local_file_path.exists():
        raise FileNotFoundError(f"Local syscall definition for {arch} not found")

    with local_file_path.open() as f:
        return json.load(f)


@functools.cache
def resolve_syscall_number(architecture: str, name: str) -> int:
    """Resolve a syscall name to its number."""
    definitions = get_syscall_definitions(architecture)

    if name in ["all", "*", "ALL", "pkm"]:
        return -1

    for syscall in definitions["syscalls"]:
        if syscall["name"] == name:
            return syscall["number"]

    raise ValueError(f'Syscall "{name}" not found')


@functools.cache
def resolve_syscall_name(architecture: str, number: int) -> str:
    """Resolve a syscall number to its name."""
    definitions = get_syscall_definitions(architecture)

    if number == -1:
        return "all"

    for syscall in definitions["syscalls"]:
        if syscall["number"] == number:
            return syscall["name"]

    raise ValueError(f'Syscall number "{number}" not found')


@functools.cache
def resolve_syscall_arguments(architecture: str, number: int) -> list[str]:
    """Resolve a syscall number to its argument definition."""
    definitions = get_syscall_definitions(architecture)

    for syscall in definitions["syscalls"]:
        if syscall["number"] == number:
            return syscall["signature"]

    raise ValueError(f'Syscall number "{number}" not found')


@functools.cache
def get_all_syscall_numbers(architecture: str) -> list[int]:
    """Retrieves all the syscall numbers."""
    definitions = get_syscall_definitions(architecture)

    return [syscall["number"] for syscall in definitions["syscalls"]]
