#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from queue import Queue
from signal import SIG_DFL, SIGUSR1, SIGUSR2, getsignal, pthread_kill, signal
from threading import main_thread

from libdebug.liblog import liblog

_shared_exception_queue: Queue[Exception] = Queue()
_SIGNAL = SIGUSR1 # We default to SIGUSR1, but we will try to use SIGUSR2 if SIGUSR1 is already set to something else


def _sigusr_handler(_, __) -> None:
    """Signal handler for SIGUSR1/2.

    This function is called when the main thread receives a SIGUSR1/2 signal.
    It retrieves an exception from the shared queue and raises it.
    """
    ex = _shared_exception_queue.get()

    raise ex


def raise_exception_to_main_thread(ex: Exception) -> None:
    """Raise an exception to the main thread.

    Sets the exception in a shared queue, then notifies the main thread with a custom signal.

    Args:
        ex (Exception): The exception to raise.
    """
    if _SIGNAL:
        _shared_exception_queue.put(ex)

        # Notify the main thread
        pthread_kill(main_thread().ident, _SIGNAL)
    else:
        liblog.error("Could not raise exception to main thread, signal handler not available.", ex)


def setup_signal_handler() -> None:
    """Set up the signal handler for SIGUSR1.

    This function sets up a signal handler for SIGUSR1 to raise exceptions in the main thread.
    """
    global _SIGNAL

    if getsignal(_SIGNAL) == _sigusr_handler:
        # Already set up, shouldn't happen but whatever
        return

    if getsignal(_SIGNAL) != SIG_DFL:
        # SIGUSR1 is already set to something else, we can't override it. Try SIGUSR2
        if getsignal(SIGUSR2) != SIG_DFL:
            # SIGUSR2 is already set to something else, we can't override it either
            liblog.warning(
                "SIGUSR1 and SIGUSR2 are not available, cannot set up signal handler for exceptions.",
            )
            _SIGNAL = None
            return

        _SIGNAL = SIGUSR2

    signal(_SIGNAL, _sigusr_handler)
