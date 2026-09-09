#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.debugger.mixins.base import EngineBoundMixin
from libdebug.utils.container import (
    ContainerFileCache,
    detect_runtime,
    get_container_init_pid,
)


class DockerDebuggerMixin(EngineBoundMixin):
    """Enable container configuration in the debugger factory.

    Combine this mixin with Debugger (or a plugin subclass) and pass the class
    to debugger(..., cls=..., container=...). Initialization remains cooperative.
    """

    @staticmethod
    def _prepare_container(
        container: str,
        runtime: str | None,
        cache_path: str | None,
        path: str,
    ) -> tuple[str, int, ContainerFileCache, str]:
        runtime = detect_runtime(container, runtime)
        init_pid = get_container_init_pid(runtime, container)
        cache = ContainerFileCache(runtime, container, cache_path)
        return runtime, init_pid, cache, cache.copy_required_file(path)
