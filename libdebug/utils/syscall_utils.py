#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import functools
import json
import os
from pathlib import Path
import requests

from libdebug.utils.libcontext import libcontext

SYSCALLS_REMOTE = "https://syscalls.mebeim.net/db"
LOCAL_FOLDER_PATH = str((Path(__file__) / ".." / "syscalls").resolve())


def get_remote_definition_url(arch: str) -> str:
    match arch:
        case "amd64":
            return f"{SYSCALLS_REMOTE}/x86/64/x64/latest/table.json"
        case _:
            raise ValueError(f"Architecture {arch} not supported")


def fetch_remote_syscall_definition(arch: str) -> dict:
    url = get_remote_definition_url(arch)

    response = requests.get(url)
    response.raise_for_status()

    # Save the response to a local file
    with open(f"{LOCAL_FOLDER_PATH}/{arch}.json", "w") as f:
        f.write(response.text)

    return response.json()


@functools.cache
def get_syscall_definitions(arch: str) -> dict:
    if not os.path.exists(LOCAL_FOLDER_PATH):
        os.makedirs(LOCAL_FOLDER_PATH)

    if os.path.exists(f"{LOCAL_FOLDER_PATH}/{arch}.json"):
        try:
            with open(f"{LOCAL_FOLDER_PATH}/{arch}.json", "r") as f:
                return json.load(f)
        except json.decoder.JSONDecodeError:
            pass

    return fetch_remote_syscall_definition(arch)


@functools.cache
def resolve_syscall_number(name: str) -> int:
    definitions = get_syscall_definitions(libcontext.arch)

    try:
        for syscall in definitions["syscalls"]:
            if syscall["name"] == name:
                return syscall["number"]
        else:
            raise KeyError()
    except KeyError:
        raise ValueError(f'Syscall "{name}" not found')


@functools.cache
def resolve_syscall_name(number: int) -> str:
    definitions = get_syscall_definitions(libcontext.arch)

    try:
        return definitions["syscalls"][number]["name"]
    except KeyError:
        raise ValueError(f'Syscall number "{number}" not found')
