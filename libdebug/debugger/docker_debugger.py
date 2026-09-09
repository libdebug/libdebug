#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.debugger.debugger import Debugger
from libdebug.debugger.mixins.docker import DockerDebuggerMixin


class DockerDebugger(DockerDebuggerMixin, Debugger):
    """A debugger whose target runs inside a Docker-compatible container."""
