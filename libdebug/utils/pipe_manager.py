#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import time
from select import select
from typing import Tuple

from libdebug.liblog import liblog


class PipeFail(Exception):
    pass


class PipeManager:
    """Class for managing pipes of the child process"""

    _instance = None
    timeout_default: int = 2

    def __init__(self, stdin_write: int, stdout_read: int, stderr_read: int):
        """Initialization for PipeManager class.

        Args:
            stdin_write (int): file descriptor for stdin write.
            stdout_read (int): file descriptor for stdout read.
            stderr_read (int): file descriptor for stderr read.
        """

        self.stdin_write: int = stdin_write
        self.stdout_read: int = stdout_read
        self.stderr_read: int = stderr_read

    def _recv(
        self,
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
            PipeFail: no stdout pipe of the child process.
        """

        pipe_read: int

        if stderr:
            pipe_read = self.stderr_read
        else:
            pipe_read = self.stdout_read

        if not pipe_read:
            raise PipeFail("No pipe of the child process")

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
                remaining_time = (
                    None if end_time is None else max(0, end_time - time.time())
                )
                ready, _, _ = select([pipe_read], [], [], remaining_time)

                if not ready:
                    # No data ready within the remaining timeout
                    break

                data = os.read(pipe_read, numb)
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

        liblog.pipe(
            f"Received {len(data_buffer)} bytes from the child process: {data_buffer!r}"
        )
        return data_buffer

    def close(self):
        """Closes all the pipes of the child process."""
        os.close(self.stdin_write)
        os.close(self.stdout_read)
        os.close(self.stderr_read)

    def recv(self, numb: int | None = None, timeout: int = timeout_default) -> bytes:
        """Receives at most numb bytes from the child process stdout.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to None.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stdout.
        """

        return self._recv(numb=numb, timeout=timeout, stderr=False)

    def recverr(self, numb: int | None = None, timeout: int = timeout_default) -> bytes:
        """Receives at most numb bytes from the child process stderr.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to None.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stderr.
        """

        return self._recv(numb=numb, timeout=timeout, stderr=True)

    def _recvonceuntil(
        self,
        delims: bytes,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found.

        Args:
            delims (bytes): delimiters where stop.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.

        Raises:
            PipeFail: no stdout pipe of the child process.
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
            remaining_time = (
                None if end_time is None else max(0, end_time - time.time())
            )

            data = self._recv(numb=1, timeout=remaining_time, stderr=stderr)

            data_buffer += data

            if delims in data_buffer:
                # Delims reached
                if drop:
                    data_buffer = data_buffer[: -len(delims)]
                break

        return data_buffer

    def _recvuntil(
        self,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found occurences time.

        Args:
            delims (bytes): delimiters where stop.
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
            remaining_time = (
                None if end_time is None else max(0, end_time - time.time())
            )

            data_buffer += self._recvonceuntil(
                delims=delims, drop=drop, timeout=remaining_time, stderr=stderr
            )

        return data_buffer

    def recvuntil(
        self,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives data from the child process stdout until the delimiters are found.

        Args:
            delims (bytes): delimiters where stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
        """

        received = self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=False,
        )

        return received

    def recverruntil(
        self,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives data from the child process stderr until the delimiters are found.

        Args:
            delims (bytes): delimiters where stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stderr.
        """

        received = self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=True,
        )

        return received

    def recvline(
        self, numlines: int = 1, drop: bool = True, timeout: int = timeout_default
    ) -> bytes:
        """Receives numlines lines from the child process stdout.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received lines from the child process stdout.
        """

        return self.recvuntil(
            delims=b"\n", occurences=numlines, drop=drop, timeout=timeout
        )

    def recverrline(
        self, numlines: int = 1, drop: bool = True, timeout: int = timeout_default
    ) -> bytes:
        """Receives numlines lines from the child process stderr.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received lines from the child process stdout.
        """

        return self.recverruntil(
            delims=b"\n", occurences=numlines, drop=drop, timeout=timeout
        )

    def send(self, data: bytes) -> int:
        """Sends data to the child process stdin.

        Args:
            data (bytes): data to send.

        Returns:
            int: number of bytes sent.

        Raises:
            PipeFail: no stdin pipe of the child process.
        """

        if not self.stdin_write:
            raise PipeFail("No stdin pipe of the child process")

        liblog.pipe(f"Sending {len(data)} bytes to the child process: {data!r}")
        
        if isinstance(data, str):
            liblog.warning("The input data is a string, converting to bytes")
            data = data.encode()
        
        return os.write(self.stdin_write, data)

    def sendline(self, data: bytes) -> int:
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
        self,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> Tuple[bytes, int]:
        """Sends data to the child process stdin after the delimiters are found.

        Args:
            delims (bytes): delimiters where stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """

        received = self.recvuntil(
            delims=delims, occurences=occurences, drop=drop, timeout=timeout
        )
        sent = self.send(data)
        return (received, sent)

    def sendlineafter(
        self,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
    ) -> Tuple[bytes, int]:
        """Sends line to the child process stdin after the delimiters are found.

        Args:
            delims (bytes): delimiters where stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """

        received = self.recvuntil(
            delims=delims, occurences=occurences, drop=drop, timeout=timeout
        )
        sent = self.sendline(data)
        return (received, sent)
