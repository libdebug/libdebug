#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import json
import os
from pathlib import Path

import requests

SYSCALLS_REMOTE = "https://syscalls.mebeim.net/db"
LOCAL_FOLDER_PATH = (Path.home() / ".cache" / "libdebug" / "syscalls").resolve()
STATIC_FOLDER_PATH = Path(__file__).parent / "syscall_data"


def get_remote_definition_url(arch: str) -> str:
    """Get the URL of the remote syscall definition file."""
    match arch:
        case "amd64":
            return f"{SYSCALLS_REMOTE}/x86/64/x64/latest/table.json"
        case "aarch64":
            return f"{SYSCALLS_REMOTE}/arm64/64/aarch64/latest/table.json"
        case "i386":
            return f"{SYSCALLS_REMOTE}/x86/32/ia32/latest/table.json"
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


def fetch_static_syscall_definition(arch: str) -> dict:
    """Fetch the syscall definition file from the local cache."""
    local_file_path = STATIC_FOLDER_PATH / f"{arch}.json"

    if not local_file_path.exists():
        raise FileNotFoundError(f"Local syscall definition for {arch} not found")

    with local_file_path.open() as f:
        return json.load(f)


@functools.cache
def get_syscall_definitions(arch: str) -> dict:
    """Get the syscall definitions for the specified architecture."""
    try:
        LOCAL_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

        if (LOCAL_FOLDER_PATH / f"{arch}.json").exists():
            try:
                with (LOCAL_FOLDER_PATH / f"{arch}.json").open() as f:
                    return json.load(f)
            except json.decoder.JSONDecodeError:
                pass
    except OSError:
        # If we cannot create the directory, we will not be able to cache the syscall definitions
        pass

    # Let's check if LOCAL_FOLDER_PATH is even writable
    if not LOCAL_FOLDER_PATH.is_dir() or not os.access(LOCAL_FOLDER_PATH, os.W_OK):
        # Even if we attempt to fetch the remote definition, we won't be able to save them,
        # so let's fallback to the static definitions directly
        syscall_definition = fetch_static_syscall_definition(arch)
    else:
        try:
            syscall_definition = fetch_remote_syscall_definition(arch)
        except:  # noqa: E722
            # Internet is probably not available
            syscall_definition = fetch_static_syscall_definition(arch)

    return syscall_definition


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
