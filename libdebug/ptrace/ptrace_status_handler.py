#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from libdebug.ptrace.ptrace_constants import StopEvents
from libdebug.liblog import liblog
import os
import signal


class PtraceStatusHandler:
    def __init__(self, ptrace_interface: "PtraceInterface"):
        self.ptrace_interface = ptrace_interface

    def _handle_clone(self, thread_id: int):
        self.ptrace_interface.register_new_thread(thread_id)

    def _handle_exit(self, thread_id: int):
        self.ptrace_interface.unregister_thread(thread_id)

    def handle_change(self, pid: int, status: int):
        event = status >> 8
        message = self.ptrace_interface._get_event_msg()

        if os.WIFSTOPPED(status):
            signum = os.WSTOPSIG(status)
            signame = signal.Signals(signum).name
            liblog.debugger("Child process %d stopped with signal %s", pid, signame)
            match event:
                case StopEvents.CLONE_EVENT:
                    liblog.debugger(
                        "Process {} cloned, new thread_id: {}".format(pid, message)
                    )
                    self._handle_clone(message)
                case StopEvents.SECCOMP_EVENT:
                    liblog.debugger(
                        "Process {} installed a seccomp, SECCOMP_RET_DATA: {}".format(
                            pid, message
                        )
                    )
                case StopEvents.EXIT_EVENT:
                    liblog.debugger(
                        "Thread {} exited with status: {}".format(pid, message)
                    )
                    # The tracee is still alive; it needs
                    # to be PTRACE_CONTed or PTRACE_DETACHed to finish exiting.
                    # self._handle_exit(pid)

        if os.WIFEXITED(status):
            exitstatus = os.WEXITSTATUS(status)
            liblog.debugger("Child process %d exited with status %d", pid, exitstatus)
            self._handle_exit(pid)

        if os.WIFSIGNALED(status):
            termsig = os.WTERMSIG(status)
            liblog.debugger("Child process %d exited with signal %d", pid, termsig)
            self._handle_exit(pid)
