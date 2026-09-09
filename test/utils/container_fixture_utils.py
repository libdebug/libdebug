#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import subprocess
from pathlib import Path

TEST_ROOT = Path(__file__).resolve().parents[1]


def docker_command(*args, timeout=120):
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"docker {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def build_container_fixture(image):
    # This is an explicitly requested integration suite: unavailable Docker is a failure.
    docker_command("info")
    docker_command(
        "build", "-f", str(TEST_ROOT / "dockerfiles" / "container.Dockerfile"),
        "--label", "org.libdebug.test=docker",
        "-t", image, str(TEST_ROOT), timeout=300,
    )
