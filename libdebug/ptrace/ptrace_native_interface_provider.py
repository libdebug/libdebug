#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import json
from pathlib import Path
from subprocess import check_output

from libdebug.liblog import liblog
from libdebug.ptrace.native import libdebug_ptrace_binding

PTRACE_FPREGS_DEFINITION_LOCATION = (Path.home() / ".cache" / "libdebug" / "fpregs.json").resolve()
PTRACE_FPREGS_AUTODETECT_LOCATION = Path(__file__).parent / "native" / "autodetect_fpregs_layout"

if PTRACE_FPREGS_DEFINITION_LOCATION.exists():
    with PTRACE_FPREGS_DEFINITION_LOCATION.open() as f:
        try:
            PTRACE_FPREGS_DEFINITION = json.load(f)
        except json.decoder.JSONDecodeError:
            liblog.error(f"Failed to decode JSON from {PTRACE_FPREGS_DEFINITION_LOCATION}.")
            PTRACE_FPREGS_DEFINITION = None
else:
    PTRACE_FPREGS_DEFINITION_LOCATION.parent.mkdir(parents=True, exist_ok=True)
    PTRACE_FPREGS_DEFINITION = None

if not PTRACE_FPREGS_AUTODETECT_LOCATION.exists():
    raise RuntimeError(
        f"Autodetect executable for ptrace_fpregs layout not found at {PTRACE_FPREGS_AUTODETECT_LOCATION}. "
        "Please ensure the script is present in the expected location. "
        "If you are building from source, please check the Build section of the documentation. "
        "If you are using a pre-built package, please report this issue on GitHub.",
    )


def get_ptrace_fpregs_definition() -> libdebug_ptrace_binding.PtraceFPRegsStructDefinition:
    """Get the ptrace_fpregs definition from the local cache."""
    global PTRACE_FPREGS_DEFINITION

    if PTRACE_FPREGS_DEFINITION is not None:
        try:
            return libdebug_ptrace_binding.PtraceFPRegsStructDefinition(
                struct_size=PTRACE_FPREGS_DEFINITION["struct_size"],
                type=PTRACE_FPREGS_DEFINITION["type"],
                has_xsave=PTRACE_FPREGS_DEFINITION["has_xsave"],
                avx_ymm0_offset=PTRACE_FPREGS_DEFINITION.get("avx_ymm0_offset", 0),
                avx512_zmm0_offset=PTRACE_FPREGS_DEFINITION.get("avx512_zmm0_offset", 0),
                avx512_zmm1_offset=PTRACE_FPREGS_DEFINITION.get("avx512_zmm1_offset", 0),
            )
        except Exception as e:  # noqa: BLE001
            # If the definition is invalid, we can log the error or handle it as needed
            liblog.error(f"Failed to parse ptrace fpregs definition: {e}")

    # We must generate a definition file
    result = check_output(
        [str(PTRACE_FPREGS_AUTODETECT_LOCATION)],
        text=True,
    )

    try:
        PTRACE_FPREGS_DEFINITION = json.loads(result)

        with PTRACE_FPREGS_DEFINITION_LOCATION.open("w") as f:
            json.dump(PTRACE_FPREGS_DEFINITION, f, indent=4)

        return libdebug_ptrace_binding.PtraceFPRegsStructDefinition(
            struct_size=PTRACE_FPREGS_DEFINITION["struct_size"],
            type=PTRACE_FPREGS_DEFINITION["type"],
            has_xsave=PTRACE_FPREGS_DEFINITION["has_xsave"],
            avx_ymm0_offset=PTRACE_FPREGS_DEFINITION.get("avx_ymm0_offset", 0),
            avx512_zmm0_offset=PTRACE_FPREGS_DEFINITION.get("avx512_zmm0_offset", 0),
            avx512_zmm1_offset=PTRACE_FPREGS_DEFINITION.get("avx512_zmm1_offset", 0),
        )
    except json.decoder.JSONDecodeError as e:
        liblog.error(f"Failed to decode JSON from the ptrace fpregs autodetect script: {e}")
        raise RuntimeError("Failed to generate ptrace fpregs definition") from e
    except Exception as e:
        liblog.error(f"Unexpected error while generating ptrace fpregs definition: {e}")
        raise RuntimeError("Failed to generate ptrace fpregs definition") from e


def provide_new_interface() -> libdebug_ptrace_binding.LibdebugPtraceInterface:
    """Provide a new instance of the LibdebugPtraceBinding interface."""
    return libdebug_ptrace_binding.LibdebugPtraceInterface(
        get_ptrace_fpregs_definition(),
    )
