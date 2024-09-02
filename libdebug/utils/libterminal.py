#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys


class LibTerminal:
    def __init__(self: LibTerminal, prompt: bytes) -> None:
        """Initializes the LibTerminal object."""
        self._stdout_buffer: bytes = b""
        self._stdin_buffer: bytes = b""
        self._stderr_buffer: bytes = b""
        self._prompt: bytes = prompt
        self._stdout: object = sys.stdout.buffer
        self._stderr: object = sys.stderr.buffer

    @property
    def stdin_buffer(self: LibTerminal) -> bytes:
        """Returns the current stdin buffer."""
        return self._stdin_buffer

    def clear_stdin_buffer(self: LibTerminal) -> None:
        """Clears the stdin buffer."""
        self._stdin_buffer = b""

    def _clear_row(self) -> None:
        """Clears the current row."""
        number_of_chars_stdout = len(self._stdout_buffer) + len(self._stdin_buffer) + len(self._prompt)
        self._stderr.write(b"\r" + b" " * number_of_chars_stdout + b"\r")

        number_of_chars_stderr = len(self._stderr_buffer) + len(self._stdin_buffer) + len(self._prompt)
        self._stderr.write(b"\r" + b" " * number_of_chars_stderr + b"\r")

    def _write_from_stdout_manager(self, payload: bytes) -> int:
        """Writes data coming from the stdout pipe of the child process."""
        # Move the cursor to the beginning of the line
        self._clear_row()

        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the data to the console stdout
        self._stdout_buffer += payload
        if payload == b"\n":
            # Add a carriage return character at the end of the line
            self._stdout_buffer += b"\r"
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        # If the payload is a newline character, we need to clear the stdout buffer
        if payload == b"\n":
            self._stdout_buffer = b""

        return len(payload)

    def _write_from_stderr_manager(self, payload: bytes) -> int:
        """Writes data coming from the stderr pipe of the child process."""
        # Move the cursor to the beginning of the line
        self._clear_row()

        # Write the data to the console stderr
        self._stderr_buffer += payload
        if payload == b"\n":
            # Add a carriage return character at the end of the line
            self._stderr_buffer += b"\r"
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        # If the payload is a newline character, we need to clear the stderr buffer
        if payload == b"\n":
            self._stderr_buffer = b""

        return len(payload)

    def _write_from_stdin_manager(self, payload: bytes) -> int:
        """Writes data coming from the stdin pipe of the child process."""
        # Move the cursor to the beginning of the line
        self._clear_row()

        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the data to the console stdout
        self._stdin_buffer += payload
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        return len(payload)

    def _write_from_unknown_stdout_manager(self, payload: bytes | str) -> int:
        """Writes data coming from an unknown source."""
        # If the payload is a string, we need to convert it to bytes
        # (this is necessary because we do not know the source of the payload)
        if isinstance(payload, str):
            payload = payload.encode()

        # Move the cursor to the beginning of the line
        self._clear_row()

        # Replace newline characters with newline + carriage return
        payload = payload.replace(b"\n", b"\n\r")

        # Write the data to the console stderr
        self._stdout.write(payload)

        # Write the  stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()
        return len(payload)

    def _write_from_unknown_stderr_manager(self, payload: bytes | str) -> int:
        """Writes data coming from an unknown source."""
        # If the payload is a string, we need to convert it to bytes
        # (this is necessary because we do not know the source of the payload)
        if isinstance(payload, str):
            payload = payload.encode()

        # Move the cursor to the beginning of the line
        self._clear_row()

        # Replace newline characters with newline + carriage return
        payload = payload.replace(b"\n", b"\n\r")

        # Write the data to the console stderr
        self._stderr.write(payload)

        # Write the  stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()
        return len(payload)


class StdoutWrapper:
    """Wrapper around stdout to allow for custom write method."""

    def __init__(self: StdoutWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StdoutWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def write(self, payload: bytes | str, source: str | None = None) -> int:
        """Overloads the write method to allow for custom behavior."""
        if source == "stdout":
            return self._terminal._write_from_stdout_manager(payload)
        elif source == "stdin":
            return self._terminal._write_from_stdin_manager(payload)
        else:
            return self._terminal._write_from_unknown_stdout_manager(payload)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)


class StderrWrapper:
    """Wrapper around stderr to allow for custom write method."""

    def __init__(self: StderrWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StderrWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def write(self, payload: bytes | str, source: str | None = None) -> int:
        """Overloads the write method to allow for custom behavior."""
        if source == "stderr":
            return self._terminal._write_from_stderr_manager(payload)
        else:
            return self._terminal._write_from_unknown_stderr_manager(payload)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)
