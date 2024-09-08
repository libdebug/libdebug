#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import sys
import time
from select import select
from threading import Event, Thread
from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog
from libdebug.utils.ansi_escape_codes import ANSIColors
from libdebug.utils.libterminal import LibTerminal

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class LibPipe:
    """Class for managing pipes of the child process."""

    timeout_default: int = 2
    prompt_default: bytes = f"{ANSIColors.RED}$ {ANSIColors.RESET}".encode()
    end_interactive: Event = Event()

    def __init__(self: LibPipe, stdin_write: int, stdout_read: int, stderr_read: int) -> None:
        """Initializes the LibPipe class.

        Args:
            stdin_write (int): file descriptor for stdin write.
            stdout_read (int): file descriptor for stdout read.
            stderr_read (int): file descriptor for stderr read.
        """
        self.stdin_write: int = stdin_write
        self.stdout_read: int = stdout_read
        self.stderr_read: int = stderr_read
        self._internal_debugger: InternalDebugger = provide_internal_debugger(self)

    def _recv(
        self: LibPipe,
        numb: int | None = None,
        timeout: float = timeout_default,
        stderr: bool = False,
    ) -> bytes:
        """Receives at most numb bytes from the child process.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to None.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.

        Returns:
            bytes: received bytes from the child process stdout.

        Raises:
            ValueError: numb is negative.
            RuntimeError: no stdout pipe of the child process.
        """
        pipe_read: int = self.stderr_read if stderr else self.stdout_read

        if not pipe_read:
            raise RuntimeError("No pipe of the child process")

        # Buffer for the received data
        data_buffer = b""

        if numb:
            # Checking the numb
            if numb < 0:
                raise ValueError("The number of bytes to receive must be positive")

            # Setting the alarm
            end_time = time.time() + timeout
            while numb > 0:
                if end_time is not None and time.time() > end_time:
                    # Timeout reached
                    break

                # Adjust the timeout for select to the remaining time
                remaining_time = None if end_time is None else max(0, end_time - time.time())
                ready, _, _ = select([pipe_read], [], [], remaining_time)

                if not ready:
                    # No data ready within the remaining timeout
                    break

                try:
                    data = os.read(pipe_read, numb)
                except OSError as e:
                    raise RuntimeError("Broken pipe. Is the child process still running?") from e

                if not data:
                    # No more data available
                    break

                numb -= len(data)
                data_buffer += data
        else:
            ready, _, _ = select([pipe_read], [], [], timeout)

            if ready:
                # Read all available bytes up to 4096
                data = os.read(pipe_read, 4096)
                data_buffer += data

        liblog.pipe(f"Received {len(data_buffer)} bytes from the child process: {data_buffer!r}")
        return data_buffer

    def close(self: LibPipe) -> None:
        """Closes all the pipes of the child process."""
        os.close(self.stdin_write)
        os.close(self.stdout_read)
        os.close(self.stderr_read)

    def recv(self: LibPipe, numb: int | None = None, timeout: int = timeout_default) -> bytes:
        """Receives at most numb bytes from the child process stdout.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to None.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stdout.
        """
        return self._recv(numb=numb, timeout=timeout, stderr=False)

    def recverr(self: LibPipe, numb: int | None = None, timeout: int = timeout_default) -> bytes:
        """Receives at most numb bytes from the child process stderr.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to None.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stderr.
        """
        return self._recv(numb=numb, timeout=timeout, stderr=True)

    def _recvonceuntil(
        self: LibPipe,
        delims: bytes,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.

        Raises:
            RuntimeError: no stdout pipe of the child process.
            TimeoutError: timeout reached.
        """
        if isinstance(delims, str):
            liblog.warning("The delimiters are a string, converting to bytes")
            delims = delims.encode()

        # Buffer for the received data
        data_buffer = b""

        # Setting the alarm
        end_time = time.time() + timeout
        while True:
            if end_time is not None and time.time() > end_time:
                # Timeout reached
                raise TimeoutError("Timeout reached")

            # Adjust the timeout for select to the remaining time
            remaining_time = None if end_time is None else max(0, end_time - time.time())

            data = self._recv(numb=1, timeout=remaining_time, stderr=stderr)

            data_buffer += data

            if delims in data_buffer:
                # Delims reached
                if drop:
                    data_buffer = data_buffer[: -len(delims)]
                break

        return data_buffer

    def _recvuntil(
        self: LibPipe,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found occurences time.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.
        """
        if occurences <= 0:
            raise ValueError("The number of occurences to receive must be positive")

        # Buffer for the received data
        data_buffer = b""

        # Setting the alarm
        end_time = time.time() + timeout

        for _ in range(occurences):
            # Adjust the timeout for select to the remaining time
            remaining_time = None if end_time is None else max(0, end_time - time.time())

            data_buffer += self._recvonceuntil(delims=delims, drop=drop, timeout=remaining_time, stderr=stderr)

        return data_buffer

    def recvuntil(
        self: LibPipe,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives data from the child process stdout until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
        """
        return self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=False,
        )

    def recverruntil(
        self: LibPipe,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives data from the child process stderr until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stderr.
        """
        return self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=True,
        )

    def recvline(self: LibPipe, numlines: int = 1, drop: bool = True, timeout: int = timeout_default) -> bytes:
        """Receives numlines lines from the child process stdout.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received lines from the child process stdout.
        """
        return self.recvuntil(delims=b"\n", occurences=numlines, drop=drop, timeout=timeout)

    def recverrline(self: LibPipe, numlines: int = 1, drop: bool = True, timeout: int = timeout_default) -> bytes:
        """Receives numlines lines from the child process stderr.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received lines from the child process stdout.
        """
        return self.recverruntil(delims=b"\n", occurences=numlines, drop=drop, timeout=timeout)

    def send(self: LibPipe, data: bytes) -> int:
        """Sends data to the child process stdin.

        Args:
            data (bytes): data to send.

        Returns:
            int: number of bytes sent.

        Raises:
            RuntimeError: no stdin pipe of the child process.
        """
        if not self.stdin_write:
            raise RuntimeError("No stdin pipe of the child process")

        liblog.pipe(f"Sending {len(data)} bytes to the child process: {data!r}")

        if isinstance(data, str):
            liblog.warning("The input data is a string, converting to bytes")
            data = data.encode()

        try:
            number_bytes = os.write(self.stdin_write, data)
        except OSError as e:
            raise RuntimeError("Broken pipe. Is the child process still running?") from e

        return number_bytes

    def sendline(self: LibPipe, data: bytes) -> int:
        """Sends data to the child process stdin and append a newline.

        Args:
            data (bytes): data to send.

        Returns:
            int: number of bytes sent.
        """
        if isinstance(data, str):
            liblog.warning("The input data is a string, converting to bytes")
            data = data.encode()

        return self.send(data=data + b"\n")

    def sendafter(
        self: LibPipe,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> tuple[bytes, int]:
        """Sends data to the child process stdin after the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """
        received = self.recvuntil(delims=delims, occurences=occurences, drop=drop, timeout=timeout)
        sent = self.send(data)
        return (received, sent)

    def sendlineafter(
        self: LibPipe,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> tuple[bytes, int]:
        """Sends line to the child process stdin after the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """
        received = self.recvuntil(delims=delims, occurences=occurences, drop=drop, timeout=timeout)
        sent = self.sendline(data)
        return (received, sent)

    def _recv_thread(self: LibPipe) -> None:
        """Receives data from the child process."""
        stdout_is_open = True
        stderr_is_open = True

        while not self.end_interactive.is_set() and (stdout_is_open or stderr_is_open):
            # We can afford to treat stdout and stderr sequentially. This approach should also prevent
            # messing up the order of the information printed by the child process.
            # To avoid starvation, we will read at most one byte at a time and force a switch between pipes
            # upon receiving a newline character.
            if stdout_is_open:
                try:
                    while recv_stdout := self._recv(numb=1, timeout=0.05, stderr=False):
                        sys.stdout.write_known_source(payload=recv_stdout)
                        if recv_stdout == b"\n":
                            break
                except RuntimeError:
                    # The child process has closed the stdout pipe
                    liblog.warning("The stdout pipe of the child process is not available anymore")
                    stdout_is_open = False
                    continue
            if stderr_is_open:
                try:
                    while recv_stderr := self._recv(numb=1, timeout=0.05, stderr=True):
                        sys.stderr.write_known_source(payload=recv_stderr)
                        if recv_stderr == b"\n":
                            break
                except RuntimeError:
                    # The child process has closed the stderr pipe
                    liblog.warning("The stderr pipe of the child process is not available anymore")
                    stderr_is_open = False
                    continue

    def interactive(self: LibPipe, prompt: bytes = prompt_default) -> None:
        """Interacts with the child process."""
        liblog.info("Calling interactive mode")

        # Set up the terminal
        libterminal = LibTerminal(prompt=prompt)

        # We do not want interferences between the information printed in stdout and stderr by the child
        # process and the user input, so we need to handle them in distinct threads.
        thread = Thread(target=self._recv_thread)
        thread.start()

        try:
            while True:
                ready, _, _ = select([sys.stdin], [], [], 0.05)
                if ready:
                    self.send(sys.stdin.readline_known_source())
                if not self._internal_debugger.running and (
                    event_type := self._internal_debugger.resume_context.event_type
                ):
                    liblog.warning(f"The debugged process has stopped due to a {event_type} event")
                    break
        except KeyboardInterrupt:
            # Ctrl+C
            pass
        except RuntimeError:
            liblog.warning("The stdin pipe of the child process is not available anymore")
        finally:
            # Wait for the thread to finish
            self.end_interactive.set()
            thread.join()

            # Reset the terminal
            libterminal.reset()

            liblog.info("Exiting interactive mode")
