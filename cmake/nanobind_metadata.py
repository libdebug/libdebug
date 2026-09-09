"""Wheel dependencies vary with the selected nanobind distribution mode."""

import os


def dynamic_metadata(settings, project):
    mode = os.environ.get("LIBDEBUG_NANOBIND_SPLIT", "0")
    if mode not in ("0", "1"):
        raise ValueError("LIBDEBUG_NANOBIND_SPLIT must be 0 or 1")
    dependencies = list(settings["dependencies"])
    if mode == "1":
        dependencies.append("nanobind-backend>=1.0")
    return {"dependencies": dependencies}


def dynamic_wheel(settings):
    # PEP 643: an sdist can produce linked or split wheels. Its Requires-Dist
    # must not promise a fixed dependency set to installers or index clients.
    return {"dependencies": True}
