#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import os
import select
import sys
import time
from errno import EAGAIN
from threading import Event
from typing import TYPE_CHECKING

from libdebug.commlink.buffer_data import BufferData
from libdebug.commlink.libterminal import LibTerminal
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class PipeManager:
    """Class for managing pipes of the child process."""

    timeout_default: int = 2
    prompt_default: str = "$ "

    def __init__(
        self: PipeManager,
        internal_debugger: InternalDebugger,
        stdin_write: int,
        stdout_read: int,
        stderr_read: int,
    ) -> None:
        """Initializes the PipeManager class.

        Args:
            internal_debugger (InternalDebugger): instance of the internal debugger.
            stdin_write (int): file descriptor for stdin write.
            stdout_read (int): file descriptor for stdout read.
            stderr_read (int): file descriptor for stderr read.
        """
        self._stdin_write: int = stdin_write
        self._stdout_read: int = stdout_read
        self._stderr_read: int = stderr_read
        self._stderr_is_open: bool = True
        self._stdout_is_open: bool = True
        self._internal_debugger = internal_debugger

        self.__stdout_buffer: BufferData = BufferData(b"")
        self.__stderr_buffer: BufferData = BufferData(b"")

        self.__end_interactive_event: Event = Event()

    def _raw_recv(
        self: PipeManager,
        numb: int | None = None,
        timeout: float | None = None,
        stderr: bool = False,
    ) -> int:
        """Receives at most numb bytes from the child process.

        Args:
            numb (int | None, optional): number of bytes to receive. Defaults to None.
            timeout (float, optional): timeout in seconds. Defaults to None.
            stderr (bool, optional): receive from stderr. Defaults to False.

        Returns:
            int: number of bytes received.
        """
        pipe_read: int = self._stderr_read if stderr else self._stdout_read

        if not pipe_read:
            raise RuntimeError("No pipe of the child process")

        data_buffer = self.__stderr_buffer if stderr else self.__stdout_buffer

        received_numb = 0

        if numb is not None and timeout is not None:
            # Checking the numb
            if numb < 0:
                raise ValueError("The number of bytes to receive must be positive")

            # Setting the alarm
            end_time = time.time() + timeout

            while numb > received_numb:
                if (remaining_time := max(0, end_time - time.time())) == 0:
                    # Timeout reached
                    break

                try:
                    ready, _, _ = select.select([pipe_read], [], [], remaining_time)
                    if ready:
                        data = os.read(pipe_read, 4096)
                        received_numb += len(data)
                        data_buffer.append(data)
                    else:
                        # No more data available in the pipe at the moment
                        break
                except OSError as e:
                    if e.errno != EAGAIN:
                        if stderr:
                            self._stderr_is_open = False
                        else:
                            self._stdout_is_open = False
        elif timeout is not None:
            try:
                ready, _, _ = select.select([pipe_read], [], [], timeout)
                if ready:
                    data = os.read(pipe_read, 4096)
                    received_numb += len(data)
                    data_buffer.append(data)
            except OSError as e:
                if e.errno != EAGAIN:
                    if stderr:
                        self._stderr_is_open = False
                    else:
                        self._stdout_is_open = False
        else:
            try:
                data = os.read(pipe_read, 4096)
                if data:
                    received_numb += len(data)
                    data_buffer.append(data)
            except OSError as e:
                if e.errno != EAGAIN:
                    if stderr:
                        self._stderr_is_open = False
                    else:
                        self._stdout_is_open = False

        if received_numb:
            liblog.pipe(f"{'stderr' if stderr else 'stdout'} {received_numb}B: {data_buffer[:received_numb]!r}")
        return received_numb

    def close(self: PipeManager) -> None:
        """Closes all the pipes of the child process."""
        os.close(self._stdin_write)
        os.close(self._stdout_read)
        os.close(self._stderr_read)

    def _buffered_recv(self: PipeManager, numb: int, timeout: int, stderr: bool) -> bytes:
        """Receives at most numb bytes from the child process stdout or stderr.

        Args:
            numb (int): number of bytes to receive.
            timeout (int): timeout in seconds.
            stderr (bool): receive from stderr.

        Returns:
            bytes: received bytes from the child process stdout or stderr.
        """
        data_buffer = self.__stderr_buffer if stderr else self.__stdout_buffer
        open_flag = self._stderr_is_open if stderr else self._stdout_is_open

        data_buffer_len = len(data_buffer)

        if data_buffer_len >= numb:
            # We have enough data in the buffer
            received = data_buffer[:numb]
            data_buffer.overwrite(data_buffer[numb:])
        elif open_flag:
            # We can receive more data
            remaining = numb - data_buffer_len
            self._raw_recv(numb=remaining, timeout=timeout, stderr=stderr)
            received = data_buffer[:numb]
            data_buffer.overwrite(data_buffer[numb:])
        elif data_buffer_len != 0:
            # The pipe is not available but we have some data in the buffer. We will return just that
            received = data_buffer.get_data()
            data_buffer.clear()
        else:
            # The pipe is not available and no data is buffered
            raise RuntimeError(f"Broken {'stderr' if stderr else 'stdout'} pipe. Is the child process still alive?")
        return received

    def recv(
        self: PipeManager,
        numb: int = 4096,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives at most numb bytes from the child process stdout.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to 4096.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stdout.
        """
        return self._buffered_recv(numb=numb, timeout=timeout, stderr=False)

    def recverr(
        self: PipeManager,
        numb: int = 4096,
        timeout: int = timeout_default,
    ) -> bytes:
        """Receives at most numb bytes from the child process stderr.

        Args:
            numb (int, optional): number of bytes to receive. Defaults to 4096.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.

        Returns:
            bytes: received bytes from the child process stderr.
        """
        return self._buffered_recv(numb=numb, timeout=timeout, stderr=True)

    def _recvonceuntil(
        self: PipeManager,
        delims: bytes,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
        optional: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.
        """
        if isinstance(delims, str):
            liblog.warning("The delimiters are a string, converting to bytes")
            delims = delims.encode()

        # Buffer for the received data
        data_buffer = self.__stderr_buffer if stderr else self.__stdout_buffer

        # Setting the alarm
        end_time = time.time() + timeout
        while True:
            open_flag = self._stderr_is_open if stderr else self._stdout_is_open

            if (until := data_buffer.find(delims)) != -1:
                break

            if (remaining_time := max(0, end_time - time.time())) == 0:
                raise TimeoutError("Timeout reached")

            if not open_flag:
                # The delimiters are not in the buffer and the pipe is not available
                raise RuntimeError(f"Broken {'stderr' if stderr else 'stdout'} pipe. Is the child process still alive?")

            received_numb = self._raw_recv(stderr=stderr, timeout=remaining_time)

            if (
                received_numb == 0
                and not self._internal_debugger.running
                and self._internal_debugger.is_debugging
                and (event := self._internal_debugger.resume_context.get_event_type())
            ):
                # We will not receive more data, the child process is not running
                if optional:
                    return b""
                event = self._internal_debugger.resume_context.get_event_type()
                raise RuntimeError(
                    f"Receive until error. The debugged process has stopped due to the following event(s). {event}",
                )
        received_data = data_buffer[:until]
        if not drop:
            # Include the delimiters in the received data
            received_data += data_buffer[until : until + len(delims)]
        remaining_data = data_buffer[until + len(delims) :]
        data_buffer.overwrite(remaining_data)
        return received_data

    def _recvuntil(
        self: PipeManager,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: float = timeout_default,
        stderr: bool = False,
        optional: bool = False,
    ) -> bytes:
        """Receives data from the child process until the delimiters are found occurences time.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (float, optional): timeout in seconds. Defaults to timeout_default.
            stderr (bool, optional): receive from stderr. Defaults to False.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

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

            data_buffer += self._recvonceuntil(
                delims=delims,
                drop=drop,
                timeout=remaining_time,
                stderr=stderr,
                optional=optional,
            )

        return data_buffer

    def recvuntil(
        self: PipeManager,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> bytes:
        """Receives data from the child process stdout until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.
        """
        return self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=False,
            optional=optional,
        )

    def recverruntil(
        self: PipeManager,
        delims: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> bytes:
        """Receives data from the child process stderr until the delimiters are found.

        Args:
            delims (bytes): delimiters where to stop.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stderr.
        """
        return self._recvuntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            stderr=True,
            optional=optional,
        )

    def recvline(
        self: PipeManager,
        numlines: int = 1,
        drop: bool = True,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> bytes:
        """Receives numlines lines from the child process stdout.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received lines from the child process stdout.
        """
        return self.recvuntil(delims=b"\n", occurences=numlines, drop=drop, timeout=timeout, optional=optional)

    def recverrline(
        self: PipeManager,
        numlines: int = 1,
        drop: bool = True,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> bytes:
        """Receives numlines lines from the child process stderr.

        Args:
            numlines (int, optional): number of lines to receive. Defaults to 1.
            drop (bool, optional): drop the line ending. Defaults to True.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received lines from the child process stdout.
        """
        return self.recverruntil(delims=b"\n", occurences=numlines, drop=drop, timeout=timeout, optional=optional)

    def send(self: PipeManager, data: bytes) -> int:
        """Sends data to the child process stdin.

        Args:
            data (bytes): data to send.

        Returns:
            int: number of bytes sent.

        Raises:
            RuntimeError: no stdin pipe of the child process.
        """
        if not self._stdin_write:
            raise RuntimeError("No stdin pipe of the child process")

        liblog.pipe(f"Sending {len(data)} bytes to the child process: {data!r}")

        if isinstance(data, str):
            liblog.warning("The input data is a string, converting to bytes")
            data = data.encode()

        try:
            number_bytes = os.write(self._stdin_write, data)
        except OSError as e:
            raise RuntimeError("Broken pipe. Is the child process still running?") from e

        return number_bytes

    def sendline(self: PipeManager, data: bytes) -> int:
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
        self: PipeManager,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> tuple[bytes, int]:
        """Sends data to the child process stdin after the delimiters are found in the stdout.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """
        received = self.recvuntil(delims=delims, occurences=occurences, drop=drop, timeout=timeout, optional=optional)
        sent = self.send(data)
        return (received, sent)

    def sendaftererr(
        self: PipeManager,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> tuple[bytes, int]:
        """Sends data to the child process stdin after the delimiters are found in stderr.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stderr.
            int: number of bytes sent.
        """
        received = self.recverruntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            optional=optional,
        )
        sent = self.send(data)
        return (received, sent)

    def sendlineafter(
        self: PipeManager,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> tuple[bytes, int]:
        """Sends line to the child process stdin after the delimiters are found in the stdout.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stdout.
            int: number of bytes sent.
        """
        received = self.recvuntil(delims=delims, occurences=occurences, drop=drop, timeout=timeout, optional=optional)
        sent = self.sendline(data)
        return (received, sent)

    def sendlineaftererr(
        self: PipeManager,
        delims: bytes,
        data: bytes,
        occurences: int = 1,
        drop: bool = False,
        timeout: int = timeout_default,
        optional: bool = False,
    ) -> tuple[bytes, int]:
        """Sends line to the child process stdin after the delimiters are found in the stderr.

        Args:
            delims (bytes): delimiters where to stop.
            data (bytes): data to send.
            occurences (int, optional): number of delimiters to find. Defaults to 1.
            drop (bool, optional): drop the delimiter. Defaults to False.
            timeout (int, optional): timeout in seconds. Defaults to timeout_default.
            optional (bool, optional): whether to ignore the wait for the received input if the command is executed when the process is stopped. Defaults to False.

        Returns:
            bytes: received data from the child process stderr.
            int: number of bytes sent.
        """
        received = self.recverruntil(
            delims=delims,
            occurences=occurences,
            drop=drop,
            timeout=timeout,
            optional=optional,
        )
        sent = self.sendline(data)
        return (received, sent)

    def _recv_for_interactive(self: PipeManager) -> None:
        """Receives data from the child process."""
        stdout_has_warned = False
        stderr_has_warned = False

        while not (self.__end_interactive_event.is_set() or (stdout_has_warned and stderr_has_warned)):
            # We can afford to treat stdout and stderr sequentially. This approach should also prevent
            # messing up the order of the information printed by the child process.
            # To avoid starvation, we switch between pipes upon receiving a bunch of data from one of them.
            if self._stdout_is_open:
                while True:
                    new_recv = self._raw_recv(numb=1024, timeout=0.1)
                    payload = self.__stdout_buffer.get_data()

                    if not (new_recv or payload):
                        # No more data available in the stdout pipe at the moment
                        break

                    sys.stdout.write(payload)
                    self.__stdout_buffer.clear()
            elif not stdout_has_warned:
                # The child process has closed the stdout pipe and we have to print the warning message
                liblog.warning("The stdout pipe of the child process is not available anymore")
                stdout_has_warned = True
            if self._stderr_is_open:
                while True:
                    new_recv = self._raw_recv(stderr=True, numb=1024, timeout=0.1)
                    payload = self.__stderr_buffer.get_data()

                    if not (new_recv or payload):
                        # No more data available in the stderr pipe at the moment
                        break

                    sys.stderr.write(payload)
                    self.__stderr_buffer.clear()
            elif not stderr_has_warned:
                # The child process has closed the stderr pipe
                liblog.warning("The stderr pipe of the child process is not available anymore")
                stderr_has_warned = True

    def interactive(self: PipeManager, prompt: str = prompt_default, auto_quit: bool = False) -> None:
        """Manually interact with the child process.

        Args:
            prompt (str, optional): prompt for the interactive mode. Defaults to "$ " (prompt_default).
            auto_quit (bool, optional): whether to automatically quit the interactive mode when the child process is not running. Defaults to False.
        """
        liblog.info("Calling interactive mode")

        # Set up and run the terminal
        libterminal = LibTerminal(
            self._internal_debugger, prompt, self.sendline, self.__end_interactive_event, auto_quit
        )

        # Receive data from the child process's stdout and stderr pipes
        self._recv_for_interactive()

        # Be sure that the interactive mode has ended
        # If the the stderr and stdout pipes are closed, the interactive mode will continue until the user manually
        # stops it
        self.__end_interactive_event.wait()

        # Unset the interactive mode event
        self.__end_interactive_event.clear()

        # Reset the terminal
        libterminal.reset()

        liblog.info("Exiting interactive mode")
