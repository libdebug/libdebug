#!/usr/bin/env python3

#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# This script is used to compress the syscall data files,
# removing unnecessary fields and keeping only the ones we need.
# It can also fetch the syscall definitions from a remote server.

import json
from argparse import ArgumentParser
from pathlib import Path

import requests

from libdebug.utils.libcontext import libcontext

SYSCALLS_REMOTE = "https://syscalls.mebeim.net/db"
STATIC_FOLDER_PATH = Path(__file__).parent

p = ArgumentParser(description="Update and compress syscall data files by removing unnecessary fields.")
p.add_argument(
    "--input_file",
    "-i",
    type=Path,
    help="Path to the input syscall data file.",
    dest="input_file",
)
p.add_argument(
    "--remote",
    "-r",
    action="store_true",
    help="Whether to fetch the syscall definition from the remote server.",
    default=False,
    dest="remote",
)
p.add_argument(
    "--arch",
    "-a",
    type=str,
    help="Architecture for which to fetch the syscall definitions (e.g., amd64, aarch64, i386).",
    dest="arch",
)


def get_remote_definition_url(arch: str) -> str:
    """Get the URL of the remote syscall definition file.

    Args:
        arch (str): The architecture for which to get the syscall definitions.

    Returns:
        str: The URL of the remote syscall definition file.
    """
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
    """Fetch the syscall definition file from the remote server.

    Args:
        arch (str): The architecture for which to fetch the syscall definitions.

    Returns:
        dict: The syscall definitions as a dictionary.
    """
    url = get_remote_definition_url(arch)

    response = requests.get(url, timeout=1)
    response.raise_for_status()

    return response.json()


def compress_syscall_data(data: dict, output_file: Path) -> None:
    """Compress syscall data by removing unnecessary fields.

    Args:
        data (dict): The syscall data to compress.
        output_file (Path): The path to the output file where compressed data will be saved.
    """
    compressed_data = {
        "syscalls": [
            {
                "name": syscall["name"],
                "number": syscall["number"],
                "signature": syscall["signature"],
            }
            for syscall in data.get("syscalls", [])
        ],
    }

    with output_file.open("w") as f:
        json.dump(compressed_data, f, indent=4)


if __name__ == "__main__":
    args = p.parse_args()
    if args.remote:
        if args.input_file:
            raise ValueError("Cannot specify both input file and remote fetch")

        if not args.arch:
            args.arch = libcontext.platform

        if args.arch not in ["amd64", "aarch64", "i386"]:
            raise ValueError("Architecture must be one of: amd64, aarch64, i386")

        syscalls = fetch_remote_syscall_definition(args.arch)

        compress_syscall_data(syscalls, STATIC_FOLDER_PATH / f"{args.arch}.json")
    else:
        if not args.input_file:
            raise ValueError("Input file must be specified when not fetching remotely")

        if not args.input_file.exists():
            raise FileNotFoundError(f"Input file {args.input_file} does not exist")

        with args.input_file.open() as f:
            syscalls = json.load(f)

        compress_syscall_data(syscalls, STATIC_FOLDER_PATH / f"{libcontext.platform}.json")

    print(f"Syscall data for {libcontext.platform} has been updated and compressed.")
    print(f"Output saved to {STATIC_FOLDER_PATH / f'{libcontext.platform}.json'}")
    print("Please run the tests to ensure everything is working correctly.")
