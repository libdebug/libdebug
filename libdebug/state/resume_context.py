#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from enum import Enum


class ResumeStatus(Enum):
    """
    Enum representing if the process should be resumed or not after a wait.

    Attributes:
        UNDECIDED (int): The stop reason is not managed. In this case, the decision is left to the user
        according to what specified by the force_resume parameter of the debugger.
        NOT_RESUME (int): The process should not be resumed.
        RESUME (int): The process should be resumed.
    """

    UNDECIDED: int = 0
    NOT_RESUME: int = 1
    RESUME: int = 2


class ResumeContext:
    """A class representing the context of the resume decision."""

    def __init__(self):
        self._resume: ResumeStatus = ResumeStatus.UNDECIDED
        self.force_interrupt: bool = False

    @property
    def resume(self):
        return self._resume

    @resume.setter
    def resume(self, value):
        if value == ResumeStatus.RESUME:
            if self._resume == ResumeStatus.UNDECIDED:
                self._resume = ResumeStatus.RESUME
        else:
            self._resume = value
