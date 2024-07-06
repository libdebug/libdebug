#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import json
from pathlib import Path

import requests

from libdebug.utils.libcontext import libcontext

SYSCALLS_REMOTE = "https://syscalls.mebeim.net/db"
LOCAL_FOLDER_PATH = (Path.home() / ".cache" / "libdebug" / "syscalls").resolve()


def get_remote_definition_url(arch: str) -> str:
    """Get the URL of the remote syscall definition file."""
    match arch:
        case "amd64":
            return f"{SYSCALLS_REMOTE}/x86/64/x64/latest/table.json"
        case _:
            raise ValueError(f"Architecture {arch} not supported")


def fetch_remote_syscall_definition(arch: str) -> dict:
    """Fetch the syscall definition file from the remote server."""
    url = get_remote_definition_url(arch)

    response = requests.get(url, timeout=1)
    response.raise_for_status()

    # Save the response to a local file
    with Path(f"{LOCAL_FOLDER_PATH}/{arch}.json").open("w") as f:
        f.write(response.text)

    return response.json()


@functools.cache
def get_syscall_definitions(arch: str) -> dict:
    """Get the syscall definitions for the specified architecture."""
    LOCAL_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

    if (LOCAL_FOLDER_PATH / f"{arch}.json").exists():
        try:
            with (LOCAL_FOLDER_PATH / f"{arch}.json").open() as f:
                return json.load(f)
        except json.decoder.JSONDecodeError:
            pass

    return fetch_remote_syscall_definition(arch)


@functools.cache
def resolve_syscall_number(name: str) -> int:
    """Resolve a syscall name to its number."""
    definitions = get_syscall_definitions(libcontext.arch)

    for syscall in definitions["syscalls"]:
        if syscall["name"] == name:
            return syscall["number"]

    raise ValueError(f'Syscall "{name}" not found')


@functools.cache
def resolve_syscall_name(number: int) -> str:
    """Resolve a syscall number to its name."""
    definitions = get_syscall_definitions(libcontext.arch)

    for syscall in definitions["syscalls"]:
        if syscall["number"] == number:
            return syscall["name"]

    raise ValueError(f'Syscall number "{number}" not found')


@functools.cache
def resolve_syscall_arguments(number: int) -> list[str]:
    """Resolve a syscall number to its argument definition."""
    definitions = get_syscall_definitions(libcontext.arch)

    for syscall in definitions["syscalls"]:
        if syscall["number"] == number:
            return syscall["signature"]

    raise ValueError(f'Syscall number "{number}" not found')


@functools.cache
def get_all_syscall_numbers() -> list[int]:
    """Retrieves all the syscall numbers."""
    definitions = get_syscall_definitions(libcontext.arch)

    return [syscall["number"] for syscall in definitions["syscalls"]]
