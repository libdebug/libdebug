#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import uuid

from libdebug.utils.container import SUPPORTED_RUNTIMES


SYMLINK_TARGET_BYTES = b"\x7fELF resolved target\n"

_FIXTURE_DOCKERFILE = Path(__file__).resolve().parents[1] / "dockerfiles" / "container_symlink_cp.Dockerfile"
_FIXTURE_CONTEXT = _FIXTURE_DOCKERFILE.parent


def _available_container_runtime(test_case):
    for runtime in SUPPORTED_RUNTIMES:
        if shutil.which(runtime) is None:
            continue
        result = subprocess.run(
            [runtime, "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return runtime
    test_case.skipTest("No usable Docker/Podman daemon available for real container cp test.")


@contextmanager
def symlink_cp_container(test_case):
    """Build and create the container-copy symlink fixture.

    Yields:
        tuple[str, str]: Runtime CLI name and container name.
    """
    runtime = _available_container_runtime(test_case)
    image = f"libdebug-symlink-cp-test:{uuid.uuid4().hex}"
    container = f"libdebug-symlink-cp-test-{uuid.uuid4().hex}"

    build_result = subprocess.run(
        [runtime, "build", "-f", str(_FIXTURE_DOCKERFILE), "-t", image, str(_FIXTURE_CONTEXT)],
        capture_output=True,
        text=True,
        check=False,
    )
    if build_result.returncode != 0:
        test_case.skipTest(f"{runtime} build failed: {build_result.stderr.strip()}")

    create_result = subprocess.run(
        [runtime, "create", "--name", container, image],
        capture_output=True,
        text=True,
        check=False,
    )
    if create_result.returncode != 0:
        subprocess.run(
            [runtime, "rmi", "-f", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        test_case.skipTest(f"{runtime} create failed: {create_result.stderr.strip()}")

    try:
        yield runtime, container
    finally:
        subprocess.run(
            [runtime, "rm", "-f", container],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            [runtime, "rmi", "-f", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
