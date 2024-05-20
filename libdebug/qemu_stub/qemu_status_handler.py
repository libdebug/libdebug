#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import signal
from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.state.debugging_context import provide_context

if TYPE_CHECKING:
    from libdebug.data.breakpoint import Breakpoint


class QemuStatusHandler:
    def __init__(self):
        self.context = provide_context(self)

    def _handle_trap_response(self, response: str) -> bool:
        stop_reasons = response[3:].split(";")
        stop_pairs = [reason.split(":") for reason in stop_reasons]

        for stop_pair in stop_pairs:
            stop_reason = stop_pair[0]
            stop_value = int(stop_pair[1], 16)

            if stop_reason == "thread":
                # A thread has stopped, check if it's a breakpoint
                thread = self.context.get_thread_by_id(stop_value)

                if not thread:
                    raise ValueError(f"Thread {stop_value} not found")

                ip = thread.instruction_pointer

                enabled_breakpoints = {}
                for bp in self.context.breakpoints.values():
                    if bp.enabled and not bp._disabled_for_step:
                        enabled_breakpoints[bp.address] = bp

                bp: None | "Breakpoint" = None

                if ip in enabled_breakpoints:
                    liblog.debugger(f"Breakpoint hit at {ip:x}")
                    bp = self.context.breakpoints[ip]

                if bp:
                    bp.hit_count += 1

                    if bp.callback:
                        thread._in_background_op = True
                        bp.callback(thread, bp)
                        thread._in_background_op = False
                        return True

                return False
            else:
                raise ValueError(f"Unexpected stop reason: {stop_reason}")

    def _handle_signal_response(self, response: str) -> bool:
        signal_number = int(response[1:3], 16)
        stop_signal = signal.Signals(signal_number)

        if stop_signal == signal.SIGTRAP:
            return self._handle_trap_response(response)
        else:
            raise ValueError(f"Unexpected signal received: {stop_signal}")

    def handle_response(self, response: str) -> bool:
        if response.startswith("T"):
            # Program received a signal
            return self._handle_signal_response(response)
        else:
            raise ValueError(f"Unexpected response from QEMU: {response}")
