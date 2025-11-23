#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from enum import Enum


class EventType(Enum):
    """A class representing the type of event that caused the resume decision."""

    UNKNOWN = "Unknown Event"
    BREAKPOINT = "Breakpoint"
    SYSCALL = "Syscall"
    SIGNAL = "Signal"
    USER_INTERRUPT = "User Interrupt"
    STEP = "Step"
    STARTUP = "Process Startup"
    CLONE = "Thread Clone"
    FORK = "Process Fork"
    EXIT = "Process Exit"
    SECCOMP = "Seccomp"
    EXEC = "Process Exec"
