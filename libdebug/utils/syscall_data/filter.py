#!/usr/bin/env python3

#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

# This script is used to compress the syscall data files,
# removing unnecessary fields and keeping only the ones we need.

import json
from argparse import ArgumentParser
from pathlib import Path

p = ArgumentParser(description="Compress syscall data files by removing unnecessary fields.")
p.add_argument(
    "input_file",
    type=Path,
    help="Path to the input syscall data file.",
)
p.add_argument(
    "output_file",
    type=Path,
    help="Path to the output compressed syscall data file.",
)


def compress_syscall_data(input_file: Path, output_file: Path) -> None:
    """Compress syscall data by removing unnecessary fields."""
    with input_file.open("r") as f:
        data = json.load(f)

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
    compress_syscall_data(args.input_file, args.output_file)
    print(f"Compressed syscall data saved to {args.output_file}")
